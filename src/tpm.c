/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

struct fpta_tpm {
    char *tcti_conf;
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
    ESYS_TR primary; /* cached: CreatePrimary is the slowest operation */
};

static bool check(TSS2_RC rc, const char *what)
{
    if (rc == TSS2_RC_SUCCESS) {
        return true;
    }
    fprintf(stderr, "fpta: TPM %s failed: %s\n", what, Tss2_RC_Decode(rc));
    return false;
}

static void disconnect(fpta_tpm *tpm)
{
    if (tpm->esys != NULL && tpm->primary != ESYS_TR_NONE) {
        (void)Esys_FlushContext(tpm->esys, tpm->primary);
    }
    tpm->primary = ESYS_TR_NONE;
    Esys_Finalize(&tpm->esys);
    Tss2_TctiLdr_Finalize(&tpm->tcti);
}

static bool create_primary(fpta_tpm *tpm)
{
    /* Deterministic: the same owner seed and template yield the same parent. */
    const TPM2B_PUBLIC template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA |
                                TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
            .parameters.eccDetail = {
                .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128,
                              .mode.aes = TPM2_ALG_CFB},
                .scheme.scheme = TPM2_ALG_NULL,
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
            .unique.ecc = {.x.size = 32, .y.size = 32},
        },
    };
    const TPM2B_SENSITIVE_CREATE sensitive = {0};
    const TPM2B_DATA outside = {0};
    const TPML_PCR_SELECTION pcrs = {0};
    return check(Esys_CreatePrimary(tpm->esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template,
                                    &outside, &pcrs, &tpm->primary, NULL, NULL, NULL,
                                    NULL),
                 "CreatePrimary");
}

static bool connect_tpm(fpta_tpm *tpm)
{
    if (tpm->esys != NULL && tpm->primary != ESYS_TR_NONE) {
        return true;
    }
    disconnect(tpm);
    if (!check(Tss2_TctiLdr_Initialize(tpm->tcti_conf, &tpm->tcti), "TCTI open") ||
        !check(Esys_Initialize(&tpm->esys, tpm->tcti, NULL), "ESYS init") ||
        !create_primary(tpm)) {
        disconnect(tpm);
        return false;
    }
    return true;
}

fpta_tpm *fpta_tpm_open(const char *tcti)
{
    fpta_tpm *tpm = calloc(1, sizeof *tpm);
    if (tpm == NULL) {
        return NULL;
    }
    tpm->primary = ESYS_TR_NONE;
    tpm->tcti_conf = strdup(tcti);
    if (tpm->tcti_conf == NULL) {
        free(tpm);
        return NULL;
    }
    return tpm;
}

void fpta_tpm_close(fpta_tpm *tpm)
{
    if (tpm != NULL) {
        disconnect(tpm);
        free(tpm->tcti_conf);
        free(tpm);
    }
}

bool fpta_tpm_probe(fpta_tpm *tpm)
{
    return connect_tpm(tpm);
}

static bool create_once(fpta_tpm *tpm, fpta_tpm_key *key)
{
    const TPM2B_PUBLIC template = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_NODA |
                                TPMA_OBJECT_SIGN_ENCRYPT,
            .parameters.eccDetail = {
                .symmetric.algorithm = TPM2_ALG_NULL,
                .scheme = {.scheme = TPM2_ALG_ECDSA,
                           .details.ecdsa.hashAlg = TPM2_ALG_SHA256},
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL,
            },
        },
    };
    const TPM2B_SENSITIVE_CREATE sensitive = {0};
    const TPM2B_DATA outside = {0};
    const TPML_PCR_SELECTION pcrs = {0};
    TPM2B_PRIVATE *priv = NULL;
    TPM2B_PUBLIC *pub = NULL;
    size_t off = 0;

    bool ok = check(Esys_Create(tpm->esys, tpm->primary, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                ESYS_TR_NONE, &sensitive, &template, &outside, &pcrs,
                                &priv, &pub, NULL, NULL, NULL),
                    "Create") &&
              check(Tss2_MU_TPM2B_PUBLIC_Marshal(pub, key->blob, sizeof key->blob, &off),
                    "marshal public") &&
              check(Tss2_MU_TPM2B_PRIVATE_Marshal(priv, key->blob, sizeof key->blob, &off),
                    "marshal private");
    if (ok) {
        const TPMS_ECC_POINT *point = &pub->publicArea.unique.ecc;
        ok = point->x.size <= 32 && point->y.size <= 32;
        if (ok) {
            memset(key->x, 0, sizeof key->x);
            memset(key->y, 0, sizeof key->y);
            memcpy(key->x + 32 - point->x.size, point->x.buffer, point->x.size);
            memcpy(key->y + 32 - point->y.size, point->y.buffer, point->y.size);
            key->blob_len = off;
        }
    }
    Esys_Free(priv);
    Esys_Free(pub);
    return ok;
}

static bool sign_once(fpta_tpm *tpm, const TPM2B_PUBLIC *pub, const TPM2B_PRIVATE *priv,
                      const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    ESYS_TR key = ESYS_TR_NONE;
    if (!check(Esys_Load(tpm->esys, tpm->primary, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                         ESYS_TR_NONE, priv, pub, &key),
               "Load")) {
        return false;
    }
    TPM2B_DIGEST input = {.size = 32};
    memcpy(input.buffer, digest, 32);
    const TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_NULL}; /* key's ECDSA scheme */
    const TPMT_TK_HASHCHECK ticket = {.tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL};
    TPMT_SIGNATURE *sig = NULL;
    bool ok = check(Esys_Sign(tpm->esys, key, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                              ESYS_TR_NONE, &input, &scheme, &ticket, &sig),
                    "Sign");
    if (ok) {
        const TPMS_SIGNATURE_ECDSA *e = &sig->signature.ecdsa;
        ok = sig->sigAlg == TPM2_ALG_ECDSA && e->signatureR.size <= 32 &&
             e->signatureS.size <= 32;
        if (ok) {
            memset(r, 0, 32);
            memset(s, 0, 32);
            memcpy(r + 32 - e->signatureR.size, e->signatureR.buffer, e->signatureR.size);
            memcpy(s + 32 - e->signatureS.size, e->signatureS.buffer, e->signatureS.size);
        }
    }
    Esys_Free(sig);
    (void)Esys_FlushContext(tpm->esys, key);
    return ok;
}

/* One reconnect covers handles lost across hibernate or a TPM reset. */
bool fpta_tpm_create(fpta_tpm *tpm, fpta_tpm_key *key)
{
    for (int attempt = 0; attempt < 2; attempt++) {
        if (connect_tpm(tpm) && create_once(tpm, key)) {
            return true;
        }
        disconnect(tpm);
    }
    return false;
}

bool fpta_tpm_sign(fpta_tpm *tpm, const uint8_t *blob, size_t blob_len,
                   const uint8_t digest[32], uint8_t r[32], uint8_t s[32])
{
    TPM2B_PUBLIC pub = {0};
    TPM2B_PRIVATE priv = {0};
    size_t off = 0;
    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, blob_len, &off, &pub) != TSS2_RC_SUCCESS ||
        Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, blob_len, &off, &priv) != TSS2_RC_SUCCESS ||
        off != blob_len) {
        return false;
    }
    for (int attempt = 0; attempt < 2; attempt++) {
        if (connect_tpm(tpm) && sign_once(tpm, &pub, &priv, digest, r, s)) {
            return true;
        }
        disconnect(tpm);
    }
    return false;
}
