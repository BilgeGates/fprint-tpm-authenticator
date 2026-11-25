/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#ifndef FPTA_CTAPHID_H
#define FPTA_CTAPHID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FPTA_REPORT_SIZE 64U
#define FPTA_MAX_MESSAGE 7609U /* 57 + 128 * 59 */
#define FPTA_ASSEMBLY_TIMEOUT_MS 500U

#define CTAPHID_PING 0x81U
#define CTAPHID_INIT 0x86U
#define CTAPHID_CBOR 0x90U
#define CTAPHID_CANCEL 0x91U
#define CTAPHID_KEEPALIVE 0xbbU
#define CTAPHID_ERROR 0xbfU

#define CTAPHID_ERR_INVALID_CMD 0x01U
#define CTAPHID_ERR_INVALID_LEN 0x03U
#define CTAPHID_ERR_INVALID_SEQ 0x04U
#define CTAPHID_ERR_MSG_TIMEOUT 0x05U
#define CTAPHID_ERR_CHANNEL_BUSY 0x06U
#define CTAPHID_ERR_INVALID_CHANNEL 0x0bU

#define CTAPHID_STATUS_PROCESSING 1U
#define CTAPHID_STATUS_UPNEEDED 2U

typedef bool (*fpta_send_fn)(void *ctx, const uint8_t report[FPTA_REPORT_SIZE]);

/* Handles one reassembled CBOR request. Writes at most cap bytes and returns
 * the response length (always >= 1: the CTAP2 status byte). */
typedef size_t (*fpta_cbor_fn)(void *ctx, uint32_t cid, const uint8_t *request,
                               size_t request_len, uint8_t *response, size_t cap);

typedef struct {
    fpta_send_fn send;
    void *send_ctx;
    fpta_cbor_fn cbor;
    void *cbor_ctx;

    uint32_t next_cid;
    /* reassembly */
    bool assembling;
    uint32_t rx_cid;
    uint8_t rx_cmd;
    uint8_t rx_seq;
    size_t rx_len;
    size_t rx_got;
    uint64_t rx_deadline_ms;
    uint8_t rx[FPTA_MAX_MESSAGE];
    /* request currently being executed */
    bool busy;
    uint32_t busy_cid;
    bool cancelled;
    bool aborted; /* INIT resync: drop the pending response */
    uint8_t request[FPTA_MAX_MESSAGE];
    uint8_t response[FPTA_MAX_MESSAGE];
} fpta_ctaphid;

void fpta_ctaphid_init(fpta_ctaphid *hid, fpta_send_fn send, void *send_ctx,
                       fpta_cbor_fn cbor, void *cbor_ctx);
/* Safe to call re-entrantly from inside the cbor handler (for CANCEL). */
void fpta_ctaphid_input(fpta_ctaphid *hid, const uint8_t *report, size_t size,
                        uint64_t now_ms);
void fpta_ctaphid_expire(fpta_ctaphid *hid, uint64_t now_ms);
void fpta_ctaphid_keepalive(fpta_ctaphid *hid, uint8_t status);

#endif
