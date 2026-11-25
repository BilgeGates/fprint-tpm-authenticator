/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/ctaphid.h"

#include <string.h>

#define BROADCAST_CID 0xffffffffU
#define INIT_DATA 57U
#define CONT_DATA 59U
#define CAPABILITIES (0x04U | 0x08U) /* CBOR, no U2F MSG */

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static bool send_message(fpta_ctaphid *hid, uint32_t cid, uint8_t cmd,
                         const uint8_t *data, size_t len)
{
    uint8_t report[FPTA_REPORT_SIZE] = {0};
    if (len > FPTA_MAX_MESSAGE) {
        return false;
    }
    put32(report, cid);
    report[4] = cmd;
    report[5] = (uint8_t)(len >> 8);
    report[6] = (uint8_t)len;
    size_t off = len < INIT_DATA ? len : INIT_DATA;
    if (off > 0) {
        memcpy(report + 7, data, off);
    }
    if (!hid->send(hid->send_ctx, report)) {
        return false;
    }
    for (uint8_t seq = 0; off < len; seq++) {
        const size_t chunk = len - off < CONT_DATA ? len - off : CONT_DATA;
        memset(report + 4, 0, sizeof report - 4);
        report[4] = seq;
        memcpy(report + 5, data + off, chunk);
        off += chunk;
        if (!hid->send(hid->send_ctx, report)) {
            return false;
        }
    }
    return true;
}

static void send_error(fpta_ctaphid *hid, uint32_t cid, uint8_t code)
{
    (void)send_message(hid, cid, CTAPHID_ERROR, &code, 1);
}

void fpta_ctaphid_init(fpta_ctaphid *hid, fpta_send_fn send, void *send_ctx,
                       fpta_cbor_fn cbor, void *cbor_ctx)
{
    memset(hid, 0, sizeof *hid);
    hid->send = send;
    hid->send_ctx = send_ctx;
    hid->cbor = cbor;
    hid->cbor_ctx = cbor_ctx;
    hid->next_cid = 1;
}

static void handle_init(fpta_ctaphid *hid, uint32_t cid, const uint8_t *report,
                        size_t len)
{
    if (len != 8) {
        send_error(hid, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }
    uint32_t assigned = cid;
    if (cid == BROADCAST_CID) {
        if (hid->next_cid == BROADCAST_CID) {
            send_error(hid, cid, CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }
        assigned = hid->next_cid++;
    } else {
        if (hid->assembling && hid->rx_cid == cid) {
            hid->assembling = false;
        }
        if (hid->busy && hid->busy_cid == cid) {
            hid->cancelled = true;
            hid->aborted = true;
        }
    }
    uint8_t out[17];
    memcpy(out, report + 7, 8);
    put32(out + 8, assigned);
    out[12] = 2; /* CTAPHID protocol version */
    out[13] = 0; /* device version 0.1.0 */
    out[14] = 1;
    out[15] = 0;
    out[16] = CAPABILITIES;
    (void)send_message(hid, cid, CTAPHID_INIT, out, sizeof out);
}

static void dispatch(fpta_ctaphid *hid)
{
    const uint32_t cid = hid->rx_cid;
    const uint8_t cmd = hid->rx_cmd;
    const size_t len = hid->rx_len;
    hid->assembling = false;

    if (cmd == CTAPHID_PING) {
        (void)send_message(hid, cid, CTAPHID_PING, hid->rx, len);
        return;
    }
    if (cmd != CTAPHID_CBOR) {
        send_error(hid, cid, CTAPHID_ERR_INVALID_CMD);
        return;
    }
    if (len == 0) {
        send_error(hid, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }
    memcpy(hid->request, hid->rx, len);
    hid->busy = true;
    hid->busy_cid = cid;
    hid->cancelled = false;
    hid->aborted = false;
    const size_t out = hid->cbor(hid->cbor_ctx, cid, hid->request, len,
                                 hid->response, sizeof hid->response);
    hid->busy = false;
    if (!hid->aborted) {
        (void)send_message(hid, cid, CTAPHID_CBOR, hid->response, out);
    }
    explicit_bzero(hid->request, len);
}

void fpta_ctaphid_expire(fpta_ctaphid *hid, uint64_t now_ms)
{
    if (hid->assembling && now_ms >= hid->rx_deadline_ms) {
        hid->assembling = false;
        send_error(hid, hid->rx_cid, CTAPHID_ERR_MSG_TIMEOUT);
    }
}

void fpta_ctaphid_keepalive(fpta_ctaphid *hid, uint8_t status)
{
    if (hid->busy && !hid->aborted) {
        (void)send_message(hid, hid->busy_cid, CTAPHID_KEEPALIVE, &status, 1);
    }
}

void fpta_ctaphid_input(fpta_ctaphid *hid, const uint8_t *report, size_t size,
                        uint64_t now_ms)
{
    if (size != FPTA_REPORT_SIZE) {
        return;
    }
    fpta_ctaphid_expire(hid, now_ms);

    const uint32_t cid = ((uint32_t)report[0] << 24) | ((uint32_t)report[1] << 16) |
                         ((uint32_t)report[2] << 8) | report[3];
    const bool initial = (report[4] & 0x80U) != 0;
    const bool allocated = cid != 0 && cid < hid->next_cid;
    const bool broadcast_init = cid == BROADCAST_CID && report[4] == CTAPHID_INIT;

    if (!allocated && !broadcast_init) {
        if (initial) {
            send_error(hid, cid, CTAPHID_ERR_INVALID_CHANNEL);
        }
        return;
    }

    if (!initial) {
        if (!hid->assembling || cid != hid->rx_cid) {
            return;
        }
        if (report[4] != hid->rx_seq) {
            hid->assembling = false;
            send_error(hid, cid, CTAPHID_ERR_INVALID_SEQ);
            return;
        }
        hid->rx_seq++;
        const size_t left = hid->rx_len - hid->rx_got;
        const size_t chunk = left < CONT_DATA ? left : CONT_DATA;
        memcpy(hid->rx + hid->rx_got, report + 5, chunk);
        hid->rx_got += chunk;
        if (hid->rx_got == hid->rx_len) {
            dispatch(hid);
        }
        return;
    }

    const uint8_t cmd = report[4];
    const size_t len = ((size_t)report[5] << 8) | report[6];

    if (cmd == CTAPHID_INIT) {
        handle_init(hid, cid, report, len);
        return;
    }
    if (cmd == CTAPHID_CANCEL) {
        if (hid->busy && cid == hid->busy_cid) {
            hid->cancelled = true;
        } else if (hid->assembling && cid == hid->rx_cid) {
            hid->assembling = false;
        }
        return; /* CANCEL never has its own response */
    }
    if (hid->busy || (hid->assembling && cid != hid->rx_cid)) {
        send_error(hid, cid, CTAPHID_ERR_CHANNEL_BUSY);
        return;
    }
    if (hid->assembling) {
        hid->assembling = false;
        send_error(hid, cid, CTAPHID_ERR_INVALID_SEQ);
        return;
    }
    if (len > FPTA_MAX_MESSAGE) {
        send_error(hid, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }
    hid->assembling = true;
    hid->rx_cid = cid;
    hid->rx_cmd = cmd;
    hid->rx_seq = 0;
    hid->rx_len = len;
    hid->rx_got = len < INIT_DATA ? len : INIT_DATA;
    hid->rx_deadline_ms = now_ms + FPTA_ASSEMBLY_TIMEOUT_MS;
    memcpy(hid->rx, report + 7, hid->rx_got);
    if (hid->rx_got == hid->rx_len) {
        dispatch(hid);
    }
}
