/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#ifndef FPTA_STORE_H
#define FPTA_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FPTA_CRED_ID_MAX 512U
#define FPTA_RP_ID_MAX 253U
#define FPTA_USER_ID_MAX 64U
#define FPTA_NAME_MAX 64U
#define FPTA_RK_MAX 100U

typedef struct fpta_store fpta_store;

typedef struct {
    uint32_t seq; /* creation order, newest is largest */
    char rp_id[FPTA_RP_ID_MAX + 1];
    uint8_t user_id[FPTA_USER_ID_MAX];
    size_t user_id_len;
    char name[FPTA_NAME_MAX + 1];
    char display[FPTA_NAME_MAX + 1];
    uint8_t cred_id[FPTA_CRED_ID_MAX];
    size_t cred_id_len;
} fpta_rk;

typedef enum { FPTA_SAVE_OK, FPTA_SAVE_FULL, FPTA_SAVE_ERROR } fpta_save_result;

/* Fails closed when existing state is inconsistent. Holds an exclusive lock. */
fpta_store *fpta_store_open(const char *dir);
void fpta_store_close(fpta_store *store);
const uint8_t *fpta_store_secret(const fpta_store *store); /* 32 bytes */
/* The new value is durable on disk before it is returned. */
bool fpta_store_next_counter(fpta_store *store, uint32_t *value);
/* Replaces an existing entry with the same (rp_id, user_id). */
fpta_save_result fpta_store_save_rk(fpta_store *store, const fpta_rk *rk);
/* Fills out[0..cap) newest first and returns the number of entries. */
size_t fpta_store_find_rk(fpta_store *store, const char *rp_id, fpta_rk *out, size_t cap);

#endif
