/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
/* Scripted verifier for the test binary only; the RP ID selects the outcome. */
#include "fpta/uv.h"

#include <poll.h>
#include <string.h>

fpta_uv_result fpta_uv_verify(const char *rp_id, fpta_operation op, const fpta_waiter *waiter)
{
    (void)op;
    if (strncmp(rp_id, "deny.", 5) == 0) {
        return FPTA_UV_DENIED;
    }
    if (strncmp(rp_id, "wait.", 5) == 0) {
        for (int i = 0; i < 100; i++) {
            if (waiter->tick(waiter->ctx)) {
                return FPTA_UV_CANCELLED;
            }
            (void)poll(&(struct pollfd){.fd = waiter->fd, .events = POLLIN}, 1, 50);
        }
        return FPTA_UV_TIMEOUT;
    }
    return FPTA_UV_OK;
}
