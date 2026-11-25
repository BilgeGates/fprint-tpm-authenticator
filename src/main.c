/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
/* fptad: the per-user authenticator daemon. It speaks raw 64-byte CTAPHID
 * reports over one SOCK_SEQPACKET connection (normally to fpta-broker). */
#include "fpta/ctap2.h"
#include "fpta/ctaphid.h"
#include "fpta/version.h"

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SOCKET "/run/fpta-broker.sock"
#define DEFAULT_TCTI "device:/dev/tpmrm0"
#define KEEPALIVE_MS 100U

typedef struct {
    int fd;
    bool dead;
    uint64_t last_keepalive;
    fpta_ctaphid hid;
} transport;

static volatile sig_atomic_t stopping;

static void on_signal(int number)
{
    (void)number;
    stopping = 1;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static bool send_report(void *ctx, const uint8_t report[FPTA_REPORT_SIZE])
{
    transport *t = ctx;
    if (!t->dead &&
        send(t->fd, report, FPTA_REPORT_SIZE, MSG_NOSIGNAL) != (ssize_t)FPTA_REPORT_SIZE) {
        t->dead = true;
    }
    return !t->dead;
}

/* Consumes one pending report. Returns false when nothing was available. */
static bool receive_one(transport *t)
{
    uint8_t report[FPTA_REPORT_SIZE + 1];
    const ssize_t n = recv(t->fd, report, sizeof report, MSG_DONTWAIT);
    if (n > 0) {
        fpta_ctaphid_input(&t->hid, report, (size_t)n, now_ms());
        return true;
    }
    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        t->dead = true;
    }
    return false;
}

static bool tick(void *ctx)
{
    transport *t = ctx;
    while (!t->dead && !t->hid.cancelled && receive_one(t)) {
    }
    const uint64_t now = now_ms();
    if (now - t->last_keepalive >= KEEPALIVE_MS) {
        t->last_keepalive = now;
        fpta_ctaphid_keepalive(&t->hid, CTAPHID_STATUS_UPNEEDED);
    }
    return t->dead || t->hid.cancelled || stopping != 0;
}

static int connect_socket(const char *path)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof address.sun_path) {
        return -1;
    }
    memcpy(address.sun_path, path, strlen(path) + 1);
    const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static bool default_state_dir(char *out, size_t cap)
{
    const char *data = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    int n = -1;
    if (data != NULL && data[0] == '/') {
        n = snprintf(out, cap, "%s/fpta", data);
    } else if (home != NULL && home[0] == '/') {
        char parent[4096];
        (void)snprintf(parent, sizeof parent, "%s/.local", home);
        (void)mkdir(parent, 0700);
        (void)snprintf(parent, sizeof parent, "%s/.local/share", home);
        (void)mkdir(parent, 0700);
        n = snprintf(out, cap, "%s/.local/share/fpta", home);
    }
    return n > 0 && (size_t)n < cap;
}

static void usage(FILE *out)
{
    fputs("Usage: fptad [--socket PATH | --fd N] [--state-dir DIR] [--tcti CONF]\n"
          "       fptad --check [--tcti CONF]\n"
          "       fptad --version | --help\n",
          out);
}

int main(int argc, char **argv)
{
    const char *socket_path = DEFAULT_SOCKET;
    const char *tcti = DEFAULT_TCTI;
    const char *state = NULL;
    char state_buffer[4096];
    int inherited = -1;
    bool check_only = false;

    const struct option options[] = {
        {"socket", required_argument, NULL, 's'}, {"fd", required_argument, NULL, 'f'},
        {"state-dir", required_argument, NULL, 'd'}, {"tcti", required_argument, NULL, 't'},
        {"check", no_argument, NULL, 'c'}, {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}};
    int option;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        char *end = NULL;
        long number;
        switch (option) {
        case 's': socket_path = optarg; break;
        case 'd': state = optarg; break;
        case 't': tcti = optarg; break;
        case 'c': check_only = true; break;
        case 'v': puts("fptad " FPTA_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        case 'f':
            number = strtol(optarg, &end, 10);
            if (*optarg == '\0' || *end != '\0' || number < 0 || number > 1023) {
                usage(stderr);
                return 2;
            }
            inherited = (int)number;
            break;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 2;
    }
    if (geteuid() == 0) {
        fputs("fpta: refusing to run as root\n", stderr);
        return 1;
    }
    (void)umask(077);
    (void)prctl(PR_SET_DUMPABLE, 0);

    fpta_tpm *tpm = fpta_tpm_open(tcti);
    if (tpm == NULL) {
        return 1;
    }
    if (check_only) {
        const bool ok = fpta_tpm_probe(tpm);
        puts(ok ? "TPM: OK (primary key can be created)"
                : "TPM: FAILED (is your user in the 'tss' group? log in again after adding it)");
        fpta_tpm_close(tpm);
        return ok ? 0 : 1;
    }

    if (state == NULL) {
        if (!default_state_dir(state_buffer, sizeof state_buffer)) {
            fputs("fpta: cannot determine the state directory\n", stderr);
            fpta_tpm_close(tpm);
            return 1;
        }
        state = state_buffer;
    }

    static transport t;
    int status = 1;
    fpta_store *store = fpta_store_open(state);
    fpta_waiter waiter = {.fd = -1, .tick = tick, .ctx = &t};
    fpta_ctap2 *ctap = store != NULL ? fpta_ctap2_new(tpm, store, &waiter) : NULL;
    if (ctap != NULL) {
        t.fd = inherited >= 0 ? inherited : connect_socket(socket_path);
        waiter.fd = t.fd;
        if (t.fd < 0) {
            fprintf(stderr, "fpta: cannot connect to %s: %s\n", socket_path, strerror(errno));
        } else {
            struct sigaction action = {.sa_handler = on_signal};
            (void)sigaction(SIGINT, &action, NULL);
            (void)sigaction(SIGTERM, &action, NULL);
            fpta_ctaphid_init(&t.hid, send_report, &t, fpta_ctap2_handle, ctap);
            while (!stopping && !t.dead) {
                struct pollfd p = {.fd = t.fd, .events = POLLIN};
                /* Sleep indefinitely unless a partial message needs a timeout. */
                const int ready = poll(&p, 1, t.hid.assembling ? 100 : -1);
                if (ready < 0 && errno != EINTR) {
                    break;
                }
                if (ready > 0) {
                    (void)receive_one(&t);
                }
                fpta_ctaphid_expire(&t.hid, now_ms());
            }
            status = stopping ? 0 : 1;
            (void)close(t.fd);
        }
    }
    fpta_ctap2_free(ctap);
    fpta_store_close(store);
    fpta_tpm_close(tpm);
    return status;
}
