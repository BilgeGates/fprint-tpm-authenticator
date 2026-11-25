/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#undef NDEBUG
#include "fpta/ctaphid.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t sent[200][FPTA_REPORT_SIZE];
static size_t sent_count;
static fpta_ctaphid hid;
static int cbor_calls;
static bool cancel_inside;

static bool capture(void *ctx, const uint8_t report[FPTA_REPORT_SIZE])
{
    (void)ctx;
    assert(sent_count < 200);
    memcpy(sent[sent_count++], report, FPTA_REPORT_SIZE);
    return true;
}

static void frame(uint32_t cid, uint8_t cmd, size_t len, const uint8_t *data, uint64_t now)
{
    uint8_t r[FPTA_REPORT_SIZE] = {(uint8_t)(cid >> 24), (uint8_t)(cid >> 16),
                                   (uint8_t)(cid >> 8), (uint8_t)cid, cmd,
                                   (uint8_t)(len >> 8), (uint8_t)len};
    if (data != NULL) {
        memcpy(r + 7, data, len < 57 ? len : 57);
    }
    fpta_ctaphid_input(&hid, r, sizeof r, now);
}

static void continuation(uint32_t cid, uint8_t seq, const uint8_t *data, size_t len, uint64_t now)
{
    uint8_t r[FPTA_REPORT_SIZE] = {(uint8_t)(cid >> 24), (uint8_t)(cid >> 16),
                                   (uint8_t)(cid >> 8), (uint8_t)cid, seq};
    memcpy(r + 5, data, len < 59 ? len : 59);
    fpta_ctaphid_input(&hid, r, sizeof r, now);
}

static size_t cbor(void *ctx, uint32_t cid, const uint8_t *req, size_t len, uint8_t *resp,
                   size_t cap)
{
    (void)ctx;
    (void)req;
    (void)len;
    (void)cap;
    cbor_calls++;
    if (cancel_inside) {
        sent_count = 0;
        frame(cid + 1, CTAPHID_CBOR, 1, (const uint8_t *)"\x04", 0);
        assert(sent_count == 1 && sent[0][4] == CTAPHID_ERROR &&
               sent[0][7] == CTAPHID_ERR_CHANNEL_BUSY);
        frame(cid, CTAPHID_CANCEL, 0, NULL, 0);
        assert(sent_count == 1 && hid.cancelled);
        sent_count = 0;
    }
    resp[0] = 0;
    return 1;
}

static void expect_error(uint8_t code)
{
    assert(sent_count == 1 && sent[0][4] == CTAPHID_ERROR && sent[0][7] == code);
    sent_count = 0;
}

int main(void)
{
    const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    fpta_ctaphid_init(&hid, capture, NULL, cbor, NULL);

    frame(5, CTAPHID_PING, 1, nonce, 0);
    expect_error(CTAPHID_ERR_INVALID_CHANNEL);
    frame(0xffffffffU, CTAPHID_INIT, 7, nonce, 0);
    expect_error(CTAPHID_ERR_INVALID_LEN);
    for (int i = 0; i < 2; i++) {
        frame(0xffffffffU, CTAPHID_INIT, 8, nonce, 0);
        assert(sent_count == 1 && memcmp(sent[0] + 7, nonce, 8) == 0 && sent[0][18] == i + 1);
        sent_count = 0;
    }

    /* Largest legal message: 57 + 128 * 59 bytes, echoed back intact. */
    static uint8_t big[FPTA_MAX_MESSAGE];
    for (size_t i = 0; i < sizeof big; i++) {
        big[i] = (uint8_t)(i * 7);
    }
    frame(1, CTAPHID_PING, sizeof big, big, 0);
    for (size_t seq = 0, off = 57; off < sizeof big; seq++, off += 59) {
        continuation(1, (uint8_t)seq, big + off, sizeof big - off, 1);
    }
    assert(sent_count == 129);
    assert(memcmp(sent[0] + 7, big, 57) == 0);
    for (size_t i = 1; i < 129; i++) {
        assert(sent[i][4] == i - 1 && memcmp(sent[i] + 5, big + 57 + (i - 1) * 59, 59) == 0);
    }
    sent_count = 0;

    frame(1, CTAPHID_PING, FPTA_MAX_MESSAGE + 1, big, 0);
    expect_error(CTAPHID_ERR_INVALID_LEN);
    frame(1, CTAPHID_PING, 100, big, 0);
    continuation(1, 1, big, 43, 1);
    expect_error(CTAPHID_ERR_INVALID_SEQ);
    frame(1, CTAPHID_PING, 100, big, 0);
    frame(2, CTAPHID_PING, 1, big, 1);
    expect_error(CTAPHID_ERR_CHANNEL_BUSY);
    fpta_ctaphid_expire(&hid, FPTA_ASSEMBLY_TIMEOUT_MS + 1);
    expect_error(CTAPHID_ERR_MSG_TIMEOUT);
    frame(1, 0x83, 1, big, 1000); /* U2F MSG is not advertised */
    expect_error(CTAPHID_ERR_INVALID_CMD);
    frame(1, CTAPHID_CBOR, 0, NULL, 1000);
    expect_error(CTAPHID_ERR_INVALID_LEN);

    cancel_inside = true;
    frame(1, CTAPHID_CBOR, 1, (const uint8_t *)"\x04", 1000);
    assert(cbor_calls == 1 && sent_count == 1 && sent[0][4] == CTAPHID_CBOR);

    puts("CTAPHID transport: all checks passed");
    return 0;
}
