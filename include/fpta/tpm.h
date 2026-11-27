/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#ifndef FPTA_TPM_H
#define FPTA_TPM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FPTA_TPM_BLOB_MAX 400U

typedef struct fpta_tpm fpta_tpm;

typedef struct {
    uint8_t blob[FPTA_TPM_BLOB_MAX];
    size_t blob_len;
    uint8_t x[32];
    uint8_t y[32];
} fpta_tpm_key;

fpta_tpm *fpta_tpm_open(const char *tcti);
void fpta_tpm_close(fpta_tpm *tpm);
bool fpta_tpm_probe(fpta_tpm *tpm);
bool fpta_tpm_create(fpta_tpm *tpm, fpta_tpm_key *key);
bool fpta_tpm_sign(fpta_tpm *tpm, const uint8_t *blob, size_t blob_len,
                   const uint8_t digest[32], uint8_t r[32], uint8_t s[32]);

#endif
