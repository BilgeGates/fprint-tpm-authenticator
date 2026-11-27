/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/ctap2.h"
#include "fpta/ctaphid.h"

#include <stdio.h>
#include <stdlib.h>

static bool drop(void *ctx, const uint8_t report[FPTA_REPORT_SIZE])
{
    (void)ctx;
    (void)report;
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static fpta_ctap2 *ctap;
    static fpta_ctaphid hid;
    static uint8_t response[FPTA_MAX_MESSAGE];
    if (ctap == NULL) {
        char dir[] = "/tmp/fpta-fuzz.XXXXXX";
        if (mkdtemp(dir) == NULL) {
            abort();
        }
        fpta_store *store = fpta_store_open(dir);
        ctap = fpta_ctap2_new(NULL, store, NULL);
        if (store == NULL || ctap == NULL) {
            abort();
        }
    }
    if (size < 2) {
        return 0;
    }
    if ((data[0] & 1) != 0) {
        fpta_ctaphid_init(&hid, drop, NULL, fpta_ctap2_handle, ctap);
        hid.next_cid = 4;
        for (size_t off = 1; off + FPTA_REPORT_SIZE <= size; off += FPTA_REPORT_SIZE) {
            fpta_ctaphid_input(&hid, data + off, FPTA_REPORT_SIZE, off);
        }
    } else {
        (void)fpta_ctap2_handle(ctap, 1, data + 1, size - 1, response, sizeof response);
    }
    return 0;
}
