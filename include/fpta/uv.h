/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#ifndef FPTA_UV_H
#define FPTA_UV_H

#include <stdbool.h>

typedef enum {
    FPTA_UV_OK,
    FPTA_UV_DENIED,
    FPTA_UV_TIMEOUT,
    FPTA_UV_CANCELLED,
    FPTA_UV_UNAVAILABLE
} fpta_uv_result;

typedef enum { FPTA_OP_REGISTER, FPTA_OP_SIGN_IN, FPTA_OP_SELECT } fpta_operation;

/* Supplied by the daemon so a blocking verification keeps the transport alive. */
typedef struct {
    int fd;                  /* wake-up descriptor for poll() */
    bool (*tick)(void *ctx); /* returns true when the request must be cancelled */
    void *ctx;
} fpta_waiter;

/* Link-time backend: fprintd in the daemon, a scripted fake in the test binary.
 * There is deliberately no runtime switch that bypasses verification. */
fpta_uv_result fpta_uv_verify(const char *rp_id, fpta_operation op, const fpta_waiter *waiter);

#endif
