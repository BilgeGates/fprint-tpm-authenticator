/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/tpm.h"
#include "fpta/uv.h"

#include <string.h>

bool fpta_tpm_create(fpta_tpm *tpm, fpta_tpm_key *key)
{
    (void)tpm;
    memset(key, 0x11, sizeof *key);
    key->blob_len = 200;
    return true;
}

bool fpta_tpm_sign(fpta_tpm *tpm, const uint8_t *blob, size_t blob_len,
                   const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    (void)tpm;
    (void)blob;
    (void)blob_len;
    memcpy(r, digest, 32);
    memcpy(s, digest, 32);
    return true;
}

fpta_uv_result fpta_uv_verify(const char *rp_id, fpta_operation op, const fpta_waiter *waiter)
{
    (void)rp_id;
    (void)op;
    (void)waiter;
    return FPTA_UV_OK;
}
