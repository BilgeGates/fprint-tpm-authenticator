/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#undef NDEBUG
#include "fpta/uv.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#define SERVICE "net.reactivated.Fprint"
#define DEVICE "/net/reactivated/Fprint/Device/0"
#define DEVICE_IFACE "net.reactivated.Fprint.Device"

typedef struct {
    const char *statuses;
    size_t next;
    int busy_claims;
    int log_fd;
    int prompt_fd;
    bool emit;
    sd_bus *bus;
    uint32_t prompt_id;
} mock;

static void note(mock *m, char event)
{
    assert(write(m->log_fd, &event, 1) == 1);
}

static void prompt_note(mock *m, char event)
{
    assert(write(m->prompt_fd, &event, 1) == 1);
}

static int prompt_method(sd_bus_message *msg, void *ctx, sd_bus_error *error)
{
    (void)error;
    mock *m = ctx;
    const char *name = sd_bus_message_get_member(msg);
    if (strcmp(name, "Begin") == 0) {
        const char *site = NULL;
        uint32_t op = 9;
        assert(sd_bus_message_read(msg, "su", &site, &op) >= 0);
        assert(strcmp(site, "example.com") == 0 && op == FPTA_OP_SIGN_IN);
        prompt_note(m, 'B');
        return sd_bus_reply_method_return(msg, "u", m->prompt_id = 7);
    }
    uint32_t id = 0;
    if (strcmp(name, "SetState") == 0) {
        uint32_t state = 0;
        int32_t left = 0;
        assert(sd_bus_message_read(msg, "uui", &id, &state, &left) >= 0);
        assert(id == m->prompt_id && state <= 4);
        prompt_note(m, (char)('0' + state));
    } else {
        assert(sd_bus_message_read(msg, "u", &id) >= 0 && id == m->prompt_id);
        prompt_note(m, 'E');
    }
    return sd_bus_reply_method_return(msg, "");
}

static int method(sd_bus_message *msg, void *ctx, sd_bus_error *error)
{
    mock *m = ctx;
    const char *name = sd_bus_message_get_member(msg);
    if (strcmp(name, "GetDefaultDevice") == 0) {
        return sd_bus_reply_method_return(msg, "o", DEVICE);
    }
    if (strcmp(name, "Claim") == 0) {
        if (m->busy_claims > 0) {
            m->busy_claims--;
            return sd_bus_error_set_const(error, SERVICE ".Error.AlreadyInUse", "busy");
        }
        note(m, 'C');
    } else if (strcmp(name, "VerifyStart") == 0) {
        note(m, 'S');
        m->emit = true;
    } else if (strcmp(name, "VerifyStop") == 0) {
        note(m, 'T');
    } else {
        note(m, 'R');
    }
    return sd_bus_reply_method_return(msg, "");
}

static const sd_bus_vtable prompt_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Begin", "su", "u", prompt_method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("SetState", "uui", "", prompt_method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("End", "u", "", prompt_method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("Cancelled", "u", 0),
    SD_BUS_VTABLE_END};

static const sd_bus_vtable manager_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("GetDefaultDevice", "", "o", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END};
static const sd_bus_vtable device_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Claim", "s", "", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStart", "s", "", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("VerifyStop", "", "", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Release", "", "", method, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("VerifyStatus", "sb", 0),
    SD_BUS_VTABLE_END};

static void serve(mock *m, int ready_fd)
{
    sd_bus *bus = NULL;
    assert(sd_bus_open_system(&bus) >= 0);
    assert(sd_bus_add_object_vtable(bus, NULL, "/net/reactivated/Fprint/Manager",
                                    SERVICE ".Manager", manager_vtable, m) >= 0);
    assert(sd_bus_add_object_vtable(bus, NULL, DEVICE, DEVICE_IFACE, device_vtable, m) >= 0);
    assert(sd_bus_request_name(bus, SERVICE, 0) >= 0);
    assert(sd_bus_add_object_vtable(bus, NULL, "/net/fpta/Prompt", "net.fpta.Prompt1",
                                    prompt_vtable, m) >= 0);
    assert(sd_bus_request_name(bus, "net.fpta.Prompt", 0) >= 0);
    assert(write(ready_fd, "1", 1) == 1);
    for (;;) {
        const int processed = sd_bus_process(bus, NULL);
        assert(processed >= 0);
        if (processed > 0) {
            continue;
        }
        if (m->emit) {
            m->emit = false;
            const char *status = NULL;
            int done = 1;
            switch (m->statuses[m->next] != '\0' ? m->statuses[m->next++] : 'w') {
            case 'm': status = "verify-match"; break;
            case 'n': status = "verify-no-match"; break;
            case 'r': status = "verify-retry-scan"; done = 0; m->emit = true; break;
            case 'e': status = "verify-disconnected"; break;
            case 'x':
                assert(sd_bus_emit_signal(bus, "/net/fpta/Prompt", "net.fpta.Prompt1",
                                          "Cancelled", "u", m->prompt_id) >= 0);
                break;
            default: break;
            }
            if (status != NULL) {
                assert(sd_bus_emit_signal(bus, DEVICE, DEVICE_IFACE, "VerifyStatus", "sb",
                                          status, done) >= 0);
            }
            continue;
        }
        (void)sd_bus_wait(bus, UINT64_MAX);
    }
}

static uint64_t cancel_at;

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static bool tick(void *ctx)
{
    (void)ctx;
    return cancel_at != 0 && now_ms() >= cancel_at;
}

static bool with_window;

static void read_all(int fd, char *out, size_t cap)
{
    size_t used = 0;
    ssize_t n;
    while (used < cap - 1 && (n = read(fd, out + used, cap - 1 - used)) > 0) {
        used += (size_t)n;
    }
    out[used] = '\0';
    (void)close(fd);
}

static void scenario(const char *label, const char *statuses, int busy, int cancel,
                     fpta_uv_result want, const char *want_log, const char *want_window)
{
    int ready[2], log[2], window[2];
    assert(pipe(ready) == 0 && pipe(log) == 0 && pipe(window) == 0);
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)close(log[0]);
        (void)close(window[0]);
        mock m = {.statuses = statuses, .busy_claims = busy, .log_fd = log[1],
                  .prompt_fd = window[1]};
        serve(&m, ready[1]);
        _exit(0);
    }
    (void)close(log[1]);
    (void)close(window[1]);
    char byte;
    assert(read(ready[0], &byte, 1) == 1);
    cancel_at = cancel > 0 ? now_ms() + (uint64_t)cancel : 0;
    const fpta_waiter waiter = {.fd = -1, .tick = tick};
    const fpta_uv_result got = fpta_uv_verify("example.com", FPTA_OP_SIGN_IN, &waiter);
    (void)kill(child, SIGTERM);
    (void)waitpid(child, NULL, 0);
    char events[64], shown[64];
    read_all(log[0], events, sizeof events);
    read_all(window[0], shown, sizeof shown);
    (void)close(ready[0]);
    (void)close(ready[1]);
    printf("%-34s result=%d calls=%-10s window=%s\n", label, (int)got, events, shown);
    fflush(stdout);
    assert(got == want);
    assert(strcmp(events, want_log) == 0);
    assert(strcmp(shown, with_window ? want_window : "") == 0);
}

int main(void)
{
    assert(getenv("FPTA_PRIVATE_BUS") != NULL);
    const char *bus = getenv("DBUS_SYSTEM_BUS_ADDRESS");
    assert(bus != NULL);
    for (int pass = 0; pass < 2; pass++) {
        with_window = pass == 1;
        if (with_window) {
            assert(setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1) == 0);
        } else {
            assert(unsetenv("DBUS_SESSION_BUS_ADDRESS") == 0);
        }
        printf("--- %s\n", with_window ? "with the prompt window" : "notification fallback");
        scenario("match", "m", 0, 0, FPTA_UV_OK, "CSTR", "B3E");
        scenario("bad scan, then match", "rm", 0, 0, FPTA_UV_OK, "CSTR", "B23E");
        scenario("one wrong finger, then match", "nm", 0, 0, FPTA_UV_OK, "CSTSTR", "B13E");
        scenario("three wrong fingers", "nnn", 0, 0, FPTA_UV_DENIED, "CSTSTSTR", "B114E");
        scenario("reader busy, then free", "m", 2, 0, FPTA_UV_OK, "CSTR", "B3E");
        scenario("browser cancels while waiting", "w", 0, 500, FPTA_UV_CANCELLED, "CSTR", "BE");
        scenario("reader error", "e", 0, 0, FPTA_UV_UNAVAILABLE, "CSTR", "B4E");
        if (with_window) {
            scenario("user presses Cancel in the window", "x", 0, 0, FPTA_UV_DENIED, "CSTR", "BE");
        }
    }
    puts("fprintd client: all checks passed");
    return 0;
}
