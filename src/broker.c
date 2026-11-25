/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
/* fpta-broker: the only privileged component. It creates exactly one virtual
 * HID device with a fixed FIDO report descriptor and relays 64-byte reports to
 * the active seat user. Clients never receive the /dev/uhid descriptor, so
 * they cannot create keyboards or other input devices. */
#include "fpta/version.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uhid.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>
#include <unistd.h>

#define REPORT 64U
#define SEAT_CHECK_MS 2000
/* The device is registered on the virtual bus and claims no USB vendor or
 * product ID. Browsers and libfido2 recognise FIDO devices by the HID usage
 * page in the report descriptor, not by these IDs. */
#define VENDOR_ID 0x0000
#define PRODUCT_ID 0x0000

static const uint8_t FIDO_DESCRIPTOR[] = {
    0x06, 0xd0, 0xf1, /* usage page: FIDO alliance */
    0x09, 0x01,       /* usage: U2F HID authenticator */
    0xa1, 0x01,       /* collection: application */
    0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
    0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
    0xc0};

static bool uhid_write(int fd, const struct uhid_event *event)
{
    return write(fd, event, sizeof *event) == (ssize_t)sizeof *event;
}

static int create_device(void)
{
    const int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("fpta-broker: open /dev/uhid");
        return -1;
    }
    struct uhid_event event = {.type = UHID_CREATE2};
    struct uhid_create2_req *req = &event.u.create2;
    (void)snprintf((char *)req->name, sizeof req->name, "fpta TPM Fingerprint Security Key");
    (void)snprintf((char *)req->phys, sizeof req->phys, "fpta-broker");
    req->bus = BUS_VIRTUAL;
    req->vendor = VENDOR_ID;
    req->product = PRODUCT_ID;
    req->rd_size = sizeof FIDO_DESCRIPTOR;
    memcpy(req->rd_data, FIDO_DESCRIPTOR, sizeof FIDO_DESCRIPTOR);
    if (!uhid_write(fd, &event)) {
        perror("fpta-broker: UHID_CREATE2");
        (void)close(fd);
        return -1;
    }
    return fd;
}

static bool user_is_active(uid_t uid)
{
    char **seats = NULL;
    const int count = sd_uid_get_seats(uid, 1, &seats);
    for (char **s = seats; s != NULL && *s != NULL; s++) {
        free(*s);
    }
    free(seats);
    return count > 0;
}

static bool device_to_client(int uhid, int client)
{
    struct uhid_event event = {0};
    if (read(uhid, &event, sizeof event) <= 0) {
        return false;
    }
    if (event.type == UHID_OUTPUT) {
        const uint8_t *data = event.u.output.data;
        size_t size = event.u.output.size;
        if (size == REPORT + 1 && data[0] == 0) { /* strip report number 0 */
            data++;
            size--;
        }
        /* Never block on a stalled client: drop it instead. */
        return size != REPORT ||
               send(client, data, REPORT, MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)REPORT;
    }
    if (event.type == UHID_GET_REPORT) {
        struct uhid_event reply = {.type = UHID_GET_REPORT_REPLY};
        reply.u.get_report_reply.id = event.u.get_report.id;
        reply.u.get_report_reply.err = EIO;
        return uhid_write(uhid, &reply);
    }
    if (event.type == UHID_SET_REPORT) {
        struct uhid_event reply = {.type = UHID_SET_REPORT_REPLY};
        reply.u.set_report_reply.id = event.u.set_report.id;
        reply.u.set_report_reply.err = EIO;
        return uhid_write(uhid, &reply);
    }
    return true;
}

static bool client_to_device(int client, int uhid)
{
    uint8_t report[REPORT + 1];
    if (recv(client, report, sizeof report, MSG_DONTWAIT) != (ssize_t)REPORT) {
        return false; /* closed, error, or a protocol violation */
    }
    struct uhid_event event = {.type = UHID_INPUT2};
    event.u.input2.size = REPORT;
    memcpy(event.u.input2.data, report, REPORT);
    return uhid_write(uhid, &event);
}

static void serve(int listener, int client, uid_t uid)
{
    const int uhid = create_device();
    if (uhid < 0) {
        return;
    }
    fprintf(stderr, "fpta-broker: security key attached for uid %u\n", (unsigned)uid);
    for (;;) {
        struct pollfd fds[3] = {{.fd = uhid, .events = POLLIN},
                                {.fd = client, .events = POLLIN},
                                {.fd = listener, .events = POLLIN}};
        if (poll(fds, 3, SEAT_CHECK_MS) < 0 && errno != EINTR) {
            break;
        }
        if (!user_is_active(uid)) {
            break;
        }
        if (fds[2].revents != 0) { /* one device, one owner */
            const int extra = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
            if (extra >= 0) {
                (void)close(extra);
            }
        }
        if (fds[1].revents != 0 && !client_to_device(client, uhid)) {
            break;
        }
        if (fds[0].revents != 0 && !device_to_client(uhid, client)) {
            break;
        }
    }
    (void)close(uhid); /* the kernel removes the device */
    fprintf(stderr, "fpta-broker: security key detached\n");
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("fpta-broker " FPTA_VERSION);
        return 0;
    }
    if (argc != 1 || sd_listen_fds(1) != 1 ||
        sd_is_socket_unix(SD_LISTEN_FDS_START, SOCK_SEQPACKET, 1, NULL, 0) <= 0) {
        fputs("fpta-broker is started by fpta-broker.socket\n", stderr);
        return 2;
    }
    const int listener = SD_LISTEN_FDS_START;
    for (;;) {
        const int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            perror("fpta-broker: accept");
            return 1;
        }
        struct ucred peer;
        socklen_t length = sizeof peer;
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 && peer.uid != 0 &&
            user_is_active(peer.uid)) {
            serve(listener, client, peer.uid);
        }
        (void)close(client);
    }
}
