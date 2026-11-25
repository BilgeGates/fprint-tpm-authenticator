/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
/* User verification through fprintd, with a desktop prompt naming the site. */
#include "fpta/uv.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <time.h>

#define SERVICE "net.reactivated.Fprint"
#define MANAGER_PATH "/net/reactivated/Fprint/Manager"
#define MANAGER_IFACE "net.reactivated.Fprint.Manager"
#define DEVICE_IFACE "net.reactivated.Fprint.Device"
#define TOTAL_TIMEOUT_MS 30000U
#define MAX_MISMATCHES 3
#define POLL_SLICE_MS 50

typedef struct {
    sd_bus *bus;
    const fpta_waiter *waiter;
    uint64_t deadline;
    sd_bus_message *reply;
    bool replied;
    bool have_status;
    bool done;
    char status[40];
} session;

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static int on_reply(sd_bus_message *m, void *ctx, sd_bus_error *error)
{
    (void)error;
    session *s = ctx;
    s->reply = sd_bus_message_ref(m);
    s->replied = true;
    return 1;
}

static int on_status(sd_bus_message *m, void *ctx, sd_bus_error *error)
{
    (void)error;
    session *s = ctx;
    const char *result = NULL;
    int done = 0;
    if (sd_bus_message_read(m, "sb", &result, &done) >= 0) {
        (void)snprintf(s->status, sizeof s->status, "%s", result);
        s->done = done != 0;
        s->have_status = true;
    }
    return 1;
}

/* Pumps the bus until *flag is set, staying responsive to CTAPHID_CANCEL and
 * keeping the browser informed through the waiter. */
static fpta_uv_result wait_for(session *s, const bool *flag)
{
    while (!*flag) {
        if (s->waiter->tick(s->waiter->ctx)) {
            return FPTA_UV_CANCELLED;
        }
        if (now_ms() >= s->deadline) {
            return FPTA_UV_TIMEOUT;
        }
        const int processed = sd_bus_process(s->bus, NULL);
        if (processed < 0) {
            return FPTA_UV_UNAVAILABLE;
        }
        if (processed > 0) {
            continue;
        }
        struct pollfd fds[2] = {
            {.fd = sd_bus_get_fd(s->bus), .events = (short)sd_bus_get_events(s->bus)},
            {.fd = s->waiter->fd, .events = POLLIN},
        };
        if (poll(fds, 2, POLL_SLICE_MS) < 0 && errno != EINTR) {
            return FPTA_UV_UNAVAILABLE;
        }
    }
    return FPTA_UV_OK;
}

/* Asynchronous so that a slow device open does not stall keepalives.
 * On a D-Bus error the error name is copied to failure. */
static fpta_uv_result call(session *s, const char *dest, const char *path, const char *iface,
                           const char *member, const char *arg, sd_bus_message **reply,
                           char failure[96])
{
    sd_bus_slot *slot = NULL;
    s->replied = false;
    s->reply = NULL;
    failure[0] = '\0';
    const int rc = arg != NULL
        ? sd_bus_call_method_async(s->bus, &slot, dest, path, iface, member, on_reply, s, "s", arg)
        : sd_bus_call_method_async(s->bus, &slot, dest, path, iface, member, on_reply, s, "");
    if (rc < 0) {
        return FPTA_UV_UNAVAILABLE;
    }
    fpta_uv_result result = wait_for(s, &s->replied);
    slot = sd_bus_slot_unref(slot);
    if (result != FPTA_UV_OK) {
        return result;
    }
    const sd_bus_error *error = sd_bus_message_get_error(s->reply);
    if (error != NULL) {
        (void)snprintf(failure, 96, "%s", error->name);
        fprintf(stderr, "fpta: %s failed: %s\n", member, error->name);
        result = FPTA_UV_UNAVAILABLE;
    } else if (reply != NULL) {
        *reply = sd_bus_message_ref(s->reply);
    }
    s->reply = sd_bus_message_unref(s->reply);
    return result;
}

static uint32_t notify(sd_bus *user, uint32_t replaces, const char *body)
{
    if (user == NULL) {
        return 0;
    }
    sd_bus_message *reply = NULL;
    uint32_t id = 0;
    if (sd_bus_call_method(user, "org.freedesktop.Notifications",
                           "/org/freedesktop/Notifications", "org.freedesktop.Notifications",
                           "Notify", NULL, &reply, "susssasa{sv}i", "fpta", replaces,
                           "auth-fingerprint-symbolic", "Fingerprint required: touch the sensor",
                           body, 0, 1, "urgency", "y", 2, (int)TOTAL_TIMEOUT_MS) >= 0) {
        (void)sd_bus_message_read(reply, "u", &id);
    }
    sd_bus_message_unref(reply);
    return id;
}

static void notify_close(sd_bus *user, uint32_t id)
{
    if (user != NULL && id != 0) {
        (void)sd_bus_call_method(user, "org.freedesktop.Notifications",
                                 "/org/freedesktop/Notifications",
                                 "org.freedesktop.Notifications", "CloseNotification", NULL,
                                 NULL, "u", id);
    }
}

/* One Claim ... Release cycle. */
static fpta_uv_result run_verification(session *s, sd_bus *user, uint32_t *note,
                                       const char *prompt)
{
    sd_bus_message *reply = NULL;
    sd_bus_slot *match = NULL;
    char failure[96], owner[256], device[256];
    const char *value = NULL;

    /* GetDefaultDevice activates fprintd; then pin everything to its unique name. */
    fpta_uv_result result = call(s, SERVICE, MANAGER_PATH, MANAGER_IFACE, "GetDefaultDevice",
                                 NULL, &reply, failure);
    if (result != FPTA_UV_OK) {
        return result;
    }
    if (sd_bus_message_read(reply, "o", &value) < 0) {
        sd_bus_message_unref(reply);
        return FPTA_UV_UNAVAILABLE;
    }
    (void)snprintf(device, sizeof device, "%s", value);
    reply = sd_bus_message_unref(reply);

    result = call(s, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                  "GetNameOwner", SERVICE, &reply, failure);
    if (result != FPTA_UV_OK) {
        return result;
    }
    if (sd_bus_message_read(reply, "s", &value) < 0) {
        sd_bus_message_unref(reply);
        return FPTA_UV_UNAVAILABLE;
    }
    (void)snprintf(owner, sizeof owner, "%s", value);
    sd_bus_message_unref(reply);

    /* The lock screen may hold the reader briefly: retry until the deadline. */
    for (;;) {
        result = call(s, owner, device, DEVICE_IFACE, "Claim", "", NULL, failure);
        if (result == FPTA_UV_OK) {
            break;
        }
        if (strcmp(failure, SERVICE ".Error.AlreadyInUse") != 0) {
            return result;
        }
        const uint64_t retry_at = now_ms() + 250;
        while (now_ms() < retry_at) {
            if (s->waiter->tick(s->waiter->ctx)) {
                return FPTA_UV_CANCELLED;
            }
            if (now_ms() >= s->deadline) {
                return FPTA_UV_TIMEOUT;
            }
            (void)poll(&(struct pollfd){.fd = s->waiter->fd, .events = POLLIN}, 1, POLL_SLICE_MS);
        }
    }

    bool started = false;
    if (sd_bus_match_signal(s->bus, &match, owner, device, DEVICE_IFACE, "VerifyStatus",
                            on_status, s) < 0) {
        result = FPTA_UV_UNAVAILABLE;
    }
    char retry_prompt[448];
    const char *shown = prompt;
    for (int mismatches = 0; result == FPTA_UV_OK;) {
        if (!started) {
            s->have_status = false;
            result = call(s, owner, device, DEVICE_IFACE, "VerifyStart", "any", NULL, failure);
            if (result != FPTA_UV_OK) {
                break;
            }
            started = true;
            *note = notify(user, *note, shown);
        }
        result = wait_for(s, &s->have_status);
        if (result != FPTA_UV_OK) {
            break;
        }
        s->have_status = false;
        /* Outcome only, never identities: makes every attempt auditable. */
        fprintf(stderr, "fpta: fingerprint reader: %s\n", s->status);
        if (strcmp(s->status, "verify-match") == 0 && s->done) {
            break;
        }
        if (strcmp(s->status, "verify-no-match") == 0) {
            if (++mismatches >= MAX_MISMATCHES) {
                result = FPTA_UV_DENIED;
                break;
            }
            (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "VerifyStop", NULL,
                                     NULL, "");
            started = false;
            (void)snprintf(retry_prompt, sizeof retry_prompt,
                           "Not recognised, %d attempt(s) left. %s",
                           MAX_MISMATCHES - mismatches, prompt);
            shown = retry_prompt;
        } else if (s->done || (strcmp(s->status, "verify-retry-scan") != 0 &&
                               strcmp(s->status, "verify-swipe-too-short") != 0 &&
                               strcmp(s->status, "verify-finger-not-centered") != 0 &&
                               strcmp(s->status, "verify-remove-and-retry") != 0)) {
            fprintf(stderr, "fpta: verification ended with %s\n", s->status);
            result = FPTA_UV_UNAVAILABLE;
        }
    }

    /* Cleanup is not cancellable: always give the reader back. */
    if (started) {
        (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "VerifyStop", NULL, NULL, "");
    }
    (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "Release", NULL, NULL, "");
    sd_bus_slot_unref(match);
    return result;
}

fpta_uv_result fpta_uv_verify(const char *rp_id, fpta_operation op, const fpta_waiter *waiter)
{
    session s = {.waiter = waiter, .deadline = now_ms() + TOTAL_TIMEOUT_MS};
    /* A fresh connection per request: closing it releases any pending claim. */
    if (sd_bus_open_system(&s.bus) < 0) {
        return FPTA_UV_UNAVAILABLE;
    }
    sd_bus *user = NULL;
    if (sd_bus_open_user(&user) >= 0) {
        (void)sd_bus_set_method_call_timeout(user, 1000000);
    }
    (void)sd_bus_set_method_call_timeout(s.bus, 5000000);

    /* rp_id is validated printable ASCII; strip the notification markup set. */
    char safe[254], prompt[384];
    (void)snprintf(safe, sizeof safe, "%s", rp_id);
    for (char *p = safe; *p != '\0'; p++) {
        if (*p == '<' || *p == '>' || *p == '&') {
            *p = '?';
        }
    }
    (void)snprintf(prompt, sizeof prompt, "%s: %s",
                   op == FPTA_OP_REGISTER ? "Create a passkey for"
                   : op == FPTA_OP_SIGN_IN ? "Sign in to"
                                           : "Select this security key for",
                   safe);

    uint32_t note = 0;
    const fpta_uv_result result = run_verification(&s, user, &note, prompt);
    notify_close(user, note);
    sd_bus_message_unref(s.reply);
    sd_bus_flush_close_unref(user);
    sd_bus_close_unref(s.bus);
    return result;
}
