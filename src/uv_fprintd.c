/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
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
#define PROMPT_START_MS 4000U

#define PROMPT_SERVICE "net.fpta.Prompt"
#define PROMPT_PATH "/net/fpta/Prompt"
#define PROMPT_IFACE "net.fpta.Prompt1"

enum { PROMPT_WAITING, PROMPT_NO_MATCH, PROMPT_RETRY, PROMPT_MATCHED, PROMPT_FAILED };

typedef struct {
    sd_bus *bus;
    uint32_t id;
    char owner[256];
    sd_bus_slot *cancel_slot;
    bool cancelled;
    uint32_t note;
    char text[384];
} ui;

typedef struct {
    sd_bus *bus;
    ui *ui;
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

static fpta_uv_result pump(session *s, uint64_t deadline)
{
    if (s->waiter->tick(s->waiter->ctx)) {
        return FPTA_UV_CANCELLED;
    }
    if (s->ui->cancelled) {
        return FPTA_UV_DENIED;
    }
    if (now_ms() >= deadline) {
        return FPTA_UV_TIMEOUT;
    }
    const int processed = sd_bus_process(s->bus, NULL);
    if (processed < 0) {
        return FPTA_UV_UNAVAILABLE;
    }
    int user_processed = 0;
    if (s->ui->bus != NULL && (user_processed = sd_bus_process(s->ui->bus, NULL)) < 0) {
        s->ui->bus = sd_bus_flush_close_unref(s->ui->bus);
        s->ui->id = 0;
    }
    if (processed > 0 || user_processed > 0) {
        return FPTA_UV_OK;
    }
    struct pollfd fds[3] = {
        {.fd = sd_bus_get_fd(s->bus), .events = (short)sd_bus_get_events(s->bus)},
        {.fd = s->waiter->fd, .events = POLLIN},
        {.fd = -1},
    };
    if (s->ui->bus != NULL) {
        fds[2].fd = sd_bus_get_fd(s->ui->bus);
        fds[2].events = (short)sd_bus_get_events(s->ui->bus);
    }
    if (poll(fds, 3, POLL_SLICE_MS) < 0 && errno != EINTR) {
        return FPTA_UV_UNAVAILABLE;
    }
    return FPTA_UV_OK;
}

static fpta_uv_result wait_until(session *s, const bool *flag, uint64_t deadline)
{
    while (!*flag) {
        const fpta_uv_result result = pump(s, deadline);
        if (result != FPTA_UV_OK) {
            return result;
        }
    }
    return FPTA_UV_OK;
}

static fpta_uv_result wait_for(session *s, const bool *flag)
{
    return wait_until(s, flag, s->deadline);
}

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

static int on_prompt_cancelled(sd_bus_message *m, void *ctx, sd_bus_error *error)
{
    (void)error;
    ui *u = ctx;
    uint32_t id = 0;
    if (sd_bus_message_read(m, "u", &id) >= 0 && id != 0 && id == u->id) {
        u->cancelled = true;
    }
    return 1;
}

typedef struct {
    sd_bus_message *reply;
    bool replied;
} pending;

static int on_prompt_reply(sd_bus_message *m, void *ctx, sd_bus_error *error)
{
    (void)error;
    pending *p = ctx;
    p->reply = sd_bus_message_ref(m);
    p->replied = true;
    return 1;
}

static void ui_open(session *s, const char *rp_id, fpta_operation op)
{
    ui *u = s->ui;
    if (u->bus == NULL) {
        u->note = notify(u->bus, 0, u->text);
        return;
    }
    pending p = {0};
    sd_bus_slot *slot = NULL;
    if (sd_bus_call_method_async(u->bus, &slot, PROMPT_SERVICE, PROMPT_PATH, PROMPT_IFACE,
                                 "Begin", on_prompt_reply, &p, "su", rp_id, (uint32_t)op) >= 0 &&
        wait_until(s, &p.replied, now_ms() + PROMPT_START_MS) == FPTA_UV_OK &&
        sd_bus_message_get_error(p.reply) == NULL &&
        sd_bus_message_read(p.reply, "u", &u->id) >= 0 && u->id != 0) {
        /* Accept Cancelled only from the instance that answered Begin. */
        const char *sender = sd_bus_message_get_sender(p.reply);
        (void)snprintf(u->owner, sizeof u->owner, "%s", sender != NULL ? sender : "");
        if (u->owner[0] == '\0' ||
            sd_bus_match_signal(u->bus, &u->cancel_slot, u->owner, PROMPT_PATH, PROMPT_IFACE,
                                "Cancelled", on_prompt_cancelled, u) < 0) {
            u->id = 0;
        }
    } else {
        u->id = 0;
    }
    sd_bus_slot_unref(slot);
    sd_bus_message_unref(p.reply);
    if (u->id == 0) {
        fprintf(stderr, "fpta: prompt window unavailable, using a notification\n");
        u->note = notify(u->bus, 0, u->text);
    }
}

static void ui_state(ui *u, int state, int attempts_left)
{
    if (u->id != 0) {
        (void)sd_bus_call_method_async(u->bus, NULL, u->owner, PROMPT_PATH, PROMPT_IFACE,
                                       "SetState", NULL, NULL, "uui", u->id, (uint32_t)state,
                                       (int32_t)attempts_left);
        (void)sd_bus_flush(u->bus);
    } else if (state == PROMPT_NO_MATCH) {
        char body[448];
        (void)snprintf(body, sizeof body, "Not recognised, %d attempt(s) left. %s",
                       attempts_left, u->text);
        u->note = notify(u->bus, u->note, body);
    }
}

static void ui_close(ui *u)
{
    if (u->id != 0) {
        (void)sd_bus_call_method(u->bus, u->owner, PROMPT_PATH, PROMPT_IFACE, "End", NULL,
                                 NULL, "u", u->id);
    } else {
        notify_close(u->bus, u->note);
    }
    u->cancel_slot = sd_bus_slot_unref(u->cancel_slot);
}

static fpta_uv_result run_verification(session *s)
{
    sd_bus_message *reply = NULL;
    sd_bus_slot *match = NULL;
    char failure[96], owner[256], device[256];
    const char *value = NULL;

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
            result = pump(s, s->deadline);
            if (result != FPTA_UV_OK) {
                return result;
            }
        }
    }

    bool started = false;
    if (sd_bus_match_signal(s->bus, &match, owner, device, DEVICE_IFACE, "VerifyStatus",
                            on_status, s) < 0) {
        result = FPTA_UV_UNAVAILABLE;
    }
    for (int mismatches = 0; result == FPTA_UV_OK;) {
        if (!started) {
            s->have_status = false;
            result = call(s, owner, device, DEVICE_IFACE, "VerifyStart", "any", NULL, failure);
            if (result != FPTA_UV_OK) {
                break;
            }
            started = true;
        }
        result = wait_for(s, &s->have_status);
        if (result != FPTA_UV_OK) {
            break;
        }
        s->have_status = false;
        fprintf(stderr, "fpta: fingerprint reader: %s\n", s->status);
        if (strcmp(s->status, "verify-match") == 0 && s->done) {
            ui_state(s->ui, PROMPT_MATCHED, 0);
            break;
        }
        if (strcmp(s->status, "verify-no-match") == 0) {
            if (++mismatches >= MAX_MISMATCHES) {
                ui_state(s->ui, PROMPT_FAILED, 0);
                result = FPTA_UV_DENIED;
                break;
            }
            (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "VerifyStop", NULL,
                                     NULL, "");
            started = false;
            ui_state(s->ui, PROMPT_NO_MATCH, MAX_MISMATCHES - mismatches);
        } else if (s->done || (strcmp(s->status, "verify-retry-scan") != 0 &&
                               strcmp(s->status, "verify-swipe-too-short") != 0 &&
                               strcmp(s->status, "verify-finger-not-centered") != 0 &&
                               strcmp(s->status, "verify-remove-and-retry") != 0)) {
            fprintf(stderr, "fpta: verification ended with %s\n", s->status);
            ui_state(s->ui, PROMPT_FAILED, 0);
            result = FPTA_UV_UNAVAILABLE;
        } else {
            ui_state(s->ui, PROMPT_RETRY, 0);
        }
    }

    /* Always release the reader, also after cancellation. */
    if (started) {
        (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "VerifyStop", NULL, NULL, "");
    }
    (void)sd_bus_call_method(s->bus, owner, device, DEVICE_IFACE, "Release", NULL, NULL, "");
    sd_bus_slot_unref(match);
    return result;
}

fpta_uv_result fpta_uv_verify(const char *rp_id, fpta_operation op, const fpta_waiter *waiter)
{
    ui u = {0};
    session s = {.ui = &u, .waiter = waiter, .deadline = now_ms() + TOTAL_TIMEOUT_MS};
    /* A fresh connection per request: closing it releases a stale claim. */
    if (sd_bus_open_system(&s.bus) < 0) {
        return FPTA_UV_UNAVAILABLE;
    }
    if (sd_bus_open_user(&u.bus) >= 0) {
        (void)sd_bus_set_method_call_timeout(u.bus, 1000000);
    } else {
        u.bus = NULL;
    }
    (void)sd_bus_set_method_call_timeout(s.bus, 5000000);

    char safe[254];
    (void)snprintf(safe, sizeof safe, "%s", rp_id);
    for (char *p = safe; *p != '\0'; p++) {
        if (*p == '<' || *p == '>' || *p == '&') {
            *p = '?';
        }
    }
    (void)snprintf(u.text, sizeof u.text, "%s: %s",
                   op == FPTA_OP_REGISTER ? "Create a passkey for"
                   : op == FPTA_OP_SIGN_IN ? "Sign in to"
                                           : "Select this security key for",
                   safe);

    ui_open(&s, rp_id, op);
    fpta_uv_result result = u.cancelled ? FPTA_UV_DENIED : run_verification(&s);
    if (result == FPTA_UV_DENIED && u.cancelled) {
        fprintf(stderr, "fpta: cancelled in the prompt window\n");
    }
    ui_close(&u);
    sd_bus_message_unref(s.reply);
    sd_bus_flush_close_unref(u.bus);
    sd_bus_close_unref(s.bus);
    return result;
}
