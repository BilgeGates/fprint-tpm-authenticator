/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#ifndef FPTA_CTAP2_H
#define FPTA_CTAP2_H

#include "fpta/store.h"
#include "fpta/tpm.h"
#include "fpta/uv.h"

#include <stddef.h>
#include <stdint.h>

typedef struct fpta_ctap2 fpta_ctap2;

fpta_ctap2 *fpta_ctap2_new(fpta_tpm *tpm, fpta_store *store, const fpta_waiter *waiter);
void fpta_ctap2_free(fpta_ctap2 *ctap);
/* Matches fpta_cbor_fn. */
size_t fpta_ctap2_handle(void *ctap, uint32_t cid, const uint8_t *request, size_t request_len,
                         uint8_t *response, size_t cap);

#endif
