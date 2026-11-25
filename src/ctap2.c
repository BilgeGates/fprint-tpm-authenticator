/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/ctap2.h"
#include "fpta/ctaphid.h"

#include <cbor.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    ST_OK = 0x00,
    ST_INVALID_COMMAND = 0x01,
    ST_INVALID_LENGTH = 0x03,
    ST_UNEXPECTED_TYPE = 0x11,
    ST_INVALID_CBOR = 0x12,
    ST_MISSING_PARAMETER = 0x14,
    ST_CREDENTIAL_EXCLUDED = 0x19,
    ST_UNSUPPORTED_ALGORITHM = 0x26,
    ST_OPERATION_DENIED = 0x27,
    ST_KEY_STORE_FULL = 0x28,
    ST_UNSUPPORTED_OPTION = 0x2b,
    ST_INVALID_OPTION = 0x2c,
    ST_KEEPALIVE_CANCEL = 0x2d,
    ST_NO_CREDENTIALS = 0x2e,
    ST_USER_ACTION_TIMEOUT = 0x2f,
    ST_NOT_ALLOWED = 0x30,
    ST_PIN_AUTH_INVALID = 0x33,
    ST_PIN_NOT_SET = 0x35,
    ST_OTHER = 0x7f
};

#define FLAG_UP 0x01U
#define FLAG_UV 0x04U
#define FLAG_AT 0x40U
#define NEXT_ASSERTION_MS 30000U
#define SIG_MAX 80U
#define AUTH_DATA_MAX (37U + 16U + 2U + FPTA_CRED_ID_MAX + 100U)
/* version(1) nonce(16) blob_len(2) blob HMAC(32) */
#define CRED_PREFIX 19U
#define CRED_MAC 32U

static const uint8_t AAGUID[16] = {0x66, 0x70, 0x74, 0x61, 0x2d, 0x74, 0x70, 0x6d,
                                   0x2d, 0x66, 0x69, 0x64, 0x6f, 0x32, 0x00, 0x01};

struct fpta_ctap2 {
    fpta_tpm *tpm;
    fpta_store *store;
    const fpta_waiter *waiter;
    /* getNextAssertion state */
    fpta_rk pending[FPTA_RK_MAX];
    size_t pending_count;
    size_t pending_index;
    uint32_t pending_cid;
    uint64_t pending_deadline;
    uint8_t pending_rp_hash[32];
    uint8_t pending_cdh[32];
    uint8_t pending_flags;
};

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

/* ---------- CBOR reading ---------- */

#define CBOR_MAX_DEPTH 8U

/* libcbor allocates containers from their declared size before reading the
 * elements, so bound every size by the bytes that are really there. CTAP2 also
 * forbids tags and indefinite lengths. Advances *off past one item. */
static bool cbor_bounded(const uint8_t *p, size_t len, size_t *off, unsigned depth)
{
    if (depth > CBOR_MAX_DEPTH || *off >= len) {
        return false;
    }
    const uint8_t major = p[*off] >> 5, info = p[*off] & 0x1f;
    (*off)++;
    if (info > 27) {
        return false;
    }
    uint64_t value = info;
    if (info >= 24) {
        const size_t width = (size_t)1 << (info - 24);
        if (len - *off < width) {
            return false;
        }
        value = 0;
        for (size_t i = 0; i < width; i++) {
            value = (value << 8) | p[(*off)++];
        }
    }
    switch (major) {
    case 0:
    case 1:
    case 7: /* simple values and floats: the argument is already consumed */
        return true;
    case 2:
    case 3:
        if (value > len - *off) {
            return false;
        }
        *off += (size_t)value;
        return true;
    case 4:
    case 5:
        if (value > (len - *off) / (major == 5 ? 2U : 1U)) {
            return false;
        }
        for (uint64_t i = 0; i < value * (major == 5 ? 2U : 1U); i++) {
            if (!cbor_bounded(p, len, off, depth + 1)) {
                return false;
            }
        }
        return true;
    default:
        return false;
    }
}

static cbor_item_t *map_find(const cbor_item_t *map, uint64_t int_key, const char *text_key)
{
    const struct cbor_pair *pairs = cbor_map_handle(map);
    for (size_t i = 0; i < cbor_map_size(map); i++) {
        const cbor_item_t *k = pairs[i].key;
        if (text_key == NULL) {
            if (cbor_isa_uint(k) && cbor_get_int(k) == int_key) {
                return pairs[i].value;
            }
        } else if (cbor_isa_string(k) && cbor_string_is_definite(k) &&
                   cbor_string_length(k) == strlen(text_key) &&
                   memcmp(cbor_string_handle(k), text_key, strlen(text_key)) == 0) {
            return pairs[i].value;
        }
    }
    return NULL;
}

static bool key_equal(const cbor_item_t *a, const cbor_item_t *b)
{
    if (cbor_typeof(a) != cbor_typeof(b)) {
        return false;
    }
    if (cbor_isa_uint(a) || cbor_isa_negint(a)) {
        return cbor_get_int(a) == cbor_get_int(b);
    }
    if (cbor_isa_string(a) && cbor_string_is_definite(a) && cbor_string_is_definite(b)) {
        return cbor_string_length(a) == cbor_string_length(b) &&
               memcmp(cbor_string_handle(a), cbor_string_handle(b), cbor_string_length(a)) == 0;
    }
    if (cbor_isa_bytestring(a) && cbor_bytestring_is_definite(a) &&
        cbor_bytestring_is_definite(b)) {
        return cbor_bytestring_length(a) == cbor_bytestring_length(b) &&
               memcmp(cbor_bytestring_handle(a), cbor_bytestring_handle(b),
                      cbor_bytestring_length(a)) == 0;
    }
    return true; /* other key types never occur in CTAP2; treat as clashing */
}

/* Duplicate map keys make "which value counts" ambiguous: reject them anywhere. */
static bool no_duplicate_keys(const cbor_item_t *item)
{
    if (cbor_isa_array(item)) {
        cbor_item_t **items = cbor_array_handle(item);
        for (size_t i = 0; i < cbor_array_size(item); i++) {
            if (!no_duplicate_keys(items[i])) {
                return false;
            }
        }
    } else if (cbor_isa_map(item)) {
        const struct cbor_pair *pairs = cbor_map_handle(item);
        for (size_t i = 0; i < cbor_map_size(item); i++) {
            for (size_t j = 0; j < i; j++) {
                if (key_equal(pairs[i].key, pairs[j].key)) {
                    return false;
                }
            }
            if (!no_duplicate_keys(pairs[i].value)) {
                return false;
            }
        }
    }
    return true;
}

static bool is_map(const cbor_item_t *item)
{
    return item != NULL && cbor_isa_map(item) && cbor_map_is_definite(item);
}

static bool is_array(const cbor_item_t *item)
{
    return item != NULL && cbor_isa_array(item) && cbor_array_is_definite(item);
}

static bool is_bytes(const cbor_item_t *item)
{
    return item != NULL && cbor_isa_bytestring(item) && cbor_bytestring_is_definite(item);
}

static bool is_text(const cbor_item_t *item)
{
    return item != NULL && cbor_isa_string(item) && cbor_string_is_definite(item);
}

static bool text_equals(const cbor_item_t *item, const char *value)
{
    return is_text(item) && cbor_string_length(item) == strlen(value) &&
           memcmp(cbor_string_handle(item), value, strlen(value)) == 0;
}

/* RP IDs are ASCII domain strings; rejecting the rest also keeps prompts honest. */
static bool read_rp_id(const cbor_item_t *item, char out[FPTA_RP_ID_MAX + 1])
{
    if (!is_text(item) || cbor_string_length(item) == 0 ||
        cbor_string_length(item) > FPTA_RP_ID_MAX) {
        return false;
    }
    const unsigned char *s = cbor_string_handle(item);
    for (size_t i = 0; i < cbor_string_length(item); i++) {
        if (s[i] < 0x21 || s[i] > 0x7e) {
            return false;
        }
    }
    memcpy(out, s, cbor_string_length(item));
    out[cbor_string_length(item)] = '\0';
    return true;
}

/* Optional display text, truncated on a UTF-8 boundary. */
static void read_name(const cbor_item_t *item, char out[FPTA_NAME_MAX + 1])
{
    out[0] = '\0';
    if (!is_text(item)) {
        return;
    }
    const unsigned char *s = cbor_string_handle(item);
    size_t len = cbor_string_length(item);
    if (len > FPTA_NAME_MAX) {
        len = FPTA_NAME_MAX;
        while (len > 0 && (s[len] & 0xc0) == 0x80) {
            len--;
        }
    }
    memcpy(out, s, len);
    out[len] = '\0';
}

typedef struct {
    bool rk, uv, up, has_up;
} options_t;

static uint8_t read_options(const cbor_item_t *map, options_t *opt)
{
    *opt = (options_t){.up = true};
    if (map == NULL) {
        return ST_OK;
    }
    if (!is_map(map)) {
        return ST_UNEXPECTED_TYPE;
    }
    const char *names[] = {"rk", "uv", "up"};
    for (size_t i = 0; i < 3; i++) {
        const cbor_item_t *v = map_find(map, 0, names[i]);
        if (v == NULL) {
            continue;
        }
        if (!cbor_is_bool(v)) {
            return ST_UNEXPECTED_TYPE;
        }
        const bool value = cbor_get_bool(v);
        if (i == 0) {
            opt->rk = value;
        } else if (i == 1) {
            opt->uv = value;
        } else {
            opt->up = value;
            opt->has_up = true;
        }
    }
    return ST_OK;
}

/* ---------- CBOR writing ---------- */

/* Takes ownership of both items. */
static bool put(cbor_item_t *map, cbor_item_t *key, cbor_item_t *value)
{
    const bool ok = key != NULL && value != NULL &&
                    cbor_map_add(map, (struct cbor_pair){.key = key, .value = value});
    if (key != NULL) {
        cbor_decref(&key);
    }
    if (value != NULL) {
        cbor_decref(&value);
    }
    return ok;
}

static cbor_item_t *u8(uint8_t v) { return cbor_build_uint8(v); }
static cbor_item_t *neg(uint8_t encoded) { return cbor_build_negint8(encoded); }
static cbor_item_t *text(const char *s) { return cbor_build_string(s); }
static cbor_item_t *blob(const uint8_t *p, size_t n) { return cbor_build_bytestring(p, n); }

/* Takes ownership of item. Returns the encoded size or 0. */
static size_t serialize(cbor_item_t *item, uint8_t *out, size_t cap)
{
    const size_t n = cbor_serialize(item, out, cap);
    cbor_decref(&item);
    return n;
}

static size_t reply_map(cbor_item_t *map, bool ok, uint8_t *response, size_t cap)
{
    if (ok) {
        const size_t n = serialize(map, response + 1, cap - 1);
        if (n > 0) {
            response[0] = ST_OK;
            return n + 1;
        }
    } else if (map != NULL) {
        cbor_decref(&map);
    }
    response[0] = ST_OTHER;
    return 1;
}

static size_t status(uint8_t *response, uint8_t code)
{
    response[0] = code;
    return 1;
}

/* ---------- credentials and signatures ---------- */

static bool sha256(const void *data, size_t len, uint8_t out[32])
{
    return EVP_Digest(data, len, out, NULL, EVP_sha256(), NULL) == 1;
}

static bool cred_mac(const fpta_ctap2 *ctap, const uint8_t rp_hash[32], const uint8_t *body,
                     size_t len, uint8_t mac[CRED_MAC])
{
    uint8_t input[32 + FPTA_CRED_ID_MAX];
    unsigned int out = 0;
    memcpy(input, rp_hash, 32);
    memcpy(input + 32, body, len);
    return HMAC(EVP_sha256(), fpta_store_secret(ctap->store), 32, input, 32 + len, mac,
                &out) != NULL &&
           out == CRED_MAC;
}

static size_t cred_wrap(const fpta_ctap2 *ctap, const uint8_t rp_hash[32],
                        const fpta_tpm_key *key, uint8_t out[FPTA_CRED_ID_MAX])
{
    const size_t body = CRED_PREFIX + key->blob_len;
    if (body + CRED_MAC > FPTA_CRED_ID_MAX || RAND_bytes(out + 1, 16) != 1) {
        return 0;
    }
    out[0] = 1;
    out[17] = (uint8_t)(key->blob_len >> 8);
    out[18] = (uint8_t)key->blob_len;
    memcpy(out + CRED_PREFIX, key->blob, key->blob_len);
    return cred_mac(ctap, rp_hash, out, body, out + body) ? body + CRED_MAC : 0;
}

/* Authenticates a credential ID for this RP without touching the TPM, so large
 * allow and exclude lists stay cheap and foreign IDs never reach the chip. */
static bool cred_open(const fpta_ctap2 *ctap, const uint8_t rp_hash[32], const uint8_t *id,
                      size_t len, const uint8_t **tpm_blob, size_t *tpm_blob_len)
{
    if (len <= CRED_PREFIX + CRED_MAC || len > FPTA_CRED_ID_MAX || id[0] != 1) {
        return false;
    }
    const size_t blob_len = ((size_t)id[17] << 8) | id[18];
    uint8_t mac[CRED_MAC];
    if (blob_len != len - CRED_PREFIX - CRED_MAC ||
        !cred_mac(ctap, rp_hash, id, len - CRED_MAC, mac) ||
        CRYPTO_memcmp(mac, id + len - CRED_MAC, CRED_MAC) != 0) {
        return false;
    }
    *tpm_blob = id + CRED_PREFIX;
    *tpm_blob_len = blob_len;
    return true;
}

/* Returns the first descriptor in the list that belongs to this RP. */
static uint8_t list_match(const fpta_ctap2 *ctap, const cbor_item_t *list,
                          const uint8_t rp_hash[32], const cbor_item_t **match)
{
    *match = NULL;
    if (list == NULL) {
        return ST_OK;
    }
    if (!is_array(list)) {
        return ST_UNEXPECTED_TYPE;
    }
    cbor_item_t **items = cbor_array_handle(list);
    for (size_t i = 0; i < cbor_array_size(list); i++) {
        if (!is_map(items[i])) {
            return ST_UNEXPECTED_TYPE;
        }
        const cbor_item_t *type = map_find(items[i], 0, "type");
        const cbor_item_t *id = map_find(items[i], 0, "id");
        if (!is_text(type) || !is_bytes(id)) {
            return ST_UNEXPECTED_TYPE;
        }
        const uint8_t *tpm_blob;
        size_t tpm_blob_len;
        if (*match == NULL && text_equals(type, "public-key") &&
            cred_open(ctap, rp_hash, cbor_bytestring_handle(id), cbor_bytestring_length(id),
                      &tpm_blob, &tpm_blob_len)) {
            *match = id;
        }
    }
    return ST_OK;
}

/* ES256 over authData || clientDataHash, DER encoded. */
static size_t sign_assertion(fpta_ctap2 *ctap, const uint8_t *tpm_blob, size_t tpm_blob_len,
                             const uint8_t *auth_data, size_t auth_len,
                             const uint8_t cdh[32], uint8_t out[SIG_MAX])
{
    uint8_t message[AUTH_DATA_MAX + 32], digest[32], r[32], s[32];
    if (auth_len > AUTH_DATA_MAX) {
        return 0;
    }
    memcpy(message, auth_data, auth_len);
    memcpy(message + auth_len, cdh, 32);
    if (!sha256(message, auth_len + 32, digest) ||
        !fpta_tpm_sign(ctap->tpm, tpm_blob, tpm_blob_len, digest, r, s)) {
        return 0;
    }
    size_t result = 0;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *br = BN_bin2bn(r, 32, NULL);
    BIGNUM *bs = BN_bin2bn(s, 32, NULL);
    if (sig != NULL && br != NULL && bs != NULL && ECDSA_SIG_set0(sig, br, bs) == 1) {
        br = bs = NULL; /* owned by sig now */
        const int n = i2d_ECDSA_SIG(sig, NULL);
        if (n > 0 && (size_t)n <= SIG_MAX) {
            uint8_t *p = out;
            result = (size_t)i2d_ECDSA_SIG(sig, &p);
        }
    }
    BN_free(br);
    BN_free(bs);
    ECDSA_SIG_free(sig);
    return result;
}

static void auth_header(uint8_t out[37], const uint8_t rp_hash[32], uint8_t flags,
                        uint32_t counter)
{
    memcpy(out, rp_hash, 32);
    out[32] = flags;
    out[33] = (uint8_t)(counter >> 24);
    out[34] = (uint8_t)(counter >> 16);
    out[35] = (uint8_t)(counter >> 8);
    out[36] = (uint8_t)counter;
}

static uint8_t verify_user(fpta_ctap2 *ctap, const char *rp_id, fpta_operation op)
{
    switch (fpta_uv_verify(rp_id, op, ctap->waiter)) {
    case FPTA_UV_OK:
        return ST_OK;
    case FPTA_UV_TIMEOUT:
        return ST_USER_ACTION_TIMEOUT;
    case FPTA_UV_CANCELLED:
        return ST_KEEPALIVE_CANCEL;
    default:
        return ST_OPERATION_DENIED;
    }
}

/* CTAP2.0: an empty pinUvAuthParam asks the user to pick this authenticator. */
static uint8_t reject_pin_auth(fpta_ctap2 *ctap, const cbor_item_t *param, const char *rp_id)
{
    if (!is_bytes(param)) {
        return ST_UNEXPECTED_TYPE;
    }
    if (cbor_bytestring_length(param) != 0) {
        return ST_PIN_AUTH_INVALID;
    }
    const uint8_t result = verify_user(ctap, rp_id, FPTA_OP_SELECT);
    return result == ST_OK ? ST_PIN_NOT_SET : result;
}

/* ---------- commands ---------- */

static size_t get_info(uint8_t *response, size_t cap)
{
    cbor_item_t *info = cbor_new_definite_map(8);
    cbor_item_t *versions = cbor_new_definite_array(1);
    cbor_item_t *options = cbor_new_definite_map(4);
    cbor_item_t *transports = cbor_new_definite_array(1);
    cbor_item_t *algorithms = cbor_new_definite_array(1);
    cbor_item_t *es256 = cbor_new_definite_map(2);
    cbor_item_t *version = text("FIDO_2_0");
    cbor_item_t *usb = text("usb");
    bool ok = info != NULL && versions != NULL && options != NULL && transports != NULL &&
              algorithms != NULL && es256 != NULL && version != NULL && usb != NULL &&
              cbor_array_push(versions, version) && cbor_array_push(transports, usb) &&
              put(options, text("rk"), cbor_build_bool(true)) &&
              put(options, text("up"), cbor_build_bool(true)) &&
              put(options, text("uv"), cbor_build_bool(true)) &&
              put(options, text("plat"), cbor_build_bool(false)) &&
              put(es256, text("alg"), neg(6)) &&
              put(es256, text("type"), text("public-key")) &&
              cbor_array_push(algorithms, es256);
    if (version != NULL) {
        cbor_decref(&version);
    }
    if (usb != NULL) {
        cbor_decref(&usb);
    }
    if (es256 != NULL) {
        cbor_decref(&es256);
    }
    if (ok) {
        ok = put(info, u8(1), cbor_incref(versions)) &&
             put(info, u8(3), blob(AAGUID, sizeof AAGUID)) &&
             put(info, u8(4), cbor_incref(options)) &&
             put(info, u8(5), cbor_build_uint16(FPTA_MAX_MESSAGE)) &&
             put(info, u8(7), u8(32)) &&
             put(info, u8(8), cbor_build_uint16(FPTA_CRED_ID_MAX)) &&
             put(info, u8(9), cbor_incref(transports)) &&
             put(info, u8(10), cbor_incref(algorithms));
    }
    cbor_item_t *owned[] = {versions, options, transports, algorithms};
    for (size_t i = 0; i < 4; i++) {
        if (owned[i] != NULL) {
            cbor_decref(&owned[i]);
        }
    }
    return reply_map(info, ok, response, cap);
}

static size_t cose_key(const fpta_tpm_key *key, uint8_t *out, size_t cap)
{
    cbor_item_t *map = cbor_new_definite_map(5);
    const bool ok = map != NULL && put(map, u8(1), u8(2)) && put(map, u8(3), neg(6)) &&
                    put(map, neg(0), u8(1)) && put(map, neg(1), blob(key->x, 32)) &&
                    put(map, neg(2), blob(key->y, 32));
    if (!ok) {
        if (map != NULL) {
            cbor_decref(&map);
        }
        return 0;
    }
    return serialize(map, out, cap);
}

static size_t make_credential(fpta_ctap2 *ctap, const cbor_item_t *req, uint8_t *response,
                              size_t cap)
{
    const cbor_item_t *cdh = map_find(req, 1, NULL);
    const cbor_item_t *rp = map_find(req, 2, NULL);
    const cbor_item_t *user = map_find(req, 3, NULL);
    const cbor_item_t *params = map_find(req, 4, NULL);
    if (cdh == NULL || rp == NULL || user == NULL || params == NULL) {
        return status(response, ST_MISSING_PARAMETER);
    }
    if (!is_bytes(cdh) || !is_map(rp) || !is_map(user) || !is_array(params)) {
        return status(response, ST_UNEXPECTED_TYPE);
    }
    if (cbor_bytestring_length(cdh) != 32) {
        return status(response, ST_INVALID_LENGTH);
    }
    fpta_rk record = {0};
    uint8_t rp_hash[32];
    const cbor_item_t *user_id = map_find(user, 0, "id");
    if (!read_rp_id(map_find(rp, 0, "id"), record.rp_id) || !is_bytes(user_id)) {
        return status(response, ST_UNEXPECTED_TYPE);
    }
    if (cbor_bytestring_length(user_id) == 0 ||
        cbor_bytestring_length(user_id) > FPTA_USER_ID_MAX) {
        return status(response, ST_INVALID_LENGTH);
    }
    record.user_id_len = cbor_bytestring_length(user_id);
    memcpy(record.user_id, cbor_bytestring_handle(user_id), record.user_id_len);
    read_name(map_find(user, 0, "name"), record.name);
    read_name(map_find(user, 0, "displayName"), record.display);

    const cbor_item_t *pin = map_find(req, 8, NULL);
    if (pin != NULL) {
        return status(response, reject_pin_auth(ctap, pin, record.rp_id));
    }

    bool es256 = false;
    cbor_item_t **list = cbor_array_handle(params);
    for (size_t i = 0; i < cbor_array_size(params); i++) {
        if (!is_map(list[i])) {
            return status(response, ST_UNEXPECTED_TYPE);
        }
        const cbor_item_t *alg = map_find(list[i], 0, "alg");
        es256 |= text_equals(map_find(list[i], 0, "type"), "public-key") && alg != NULL &&
                 cbor_isa_negint(alg) && cbor_get_int(alg) == 6;
    }
    if (!es256) {
        return status(response, ST_UNSUPPORTED_ALGORITHM);
    }

    options_t opt;
    uint8_t st = read_options(map_find(req, 7, NULL), &opt);
    if (st != ST_OK) {
        return status(response, st);
    }
    if (opt.has_up && !opt.up) {
        return status(response, ST_INVALID_OPTION);
    }

    const cbor_item_t *excluded = NULL;
    if (!sha256(record.rp_id, strlen(record.rp_id), rp_hash)) {
        return status(response, ST_OTHER);
    }
    st = list_match(ctap, map_find(req, 5, NULL), rp_hash, &excluded);
    if (st != ST_OK) {
        return status(response, st);
    }

    st = verify_user(ctap, record.rp_id, excluded != NULL ? FPTA_OP_SELECT : FPTA_OP_REGISTER);
    if (st != ST_OK) {
        return status(response, st);
    }
    if (excluded != NULL) {
        return status(response, ST_CREDENTIAL_EXCLUDED);
    }

    fpta_tpm_key key;
    uint32_t counter;
    if (!fpta_tpm_create(ctap->tpm, &key)) {
        return status(response, ST_OTHER);
    }
    record.cred_id_len = cred_wrap(ctap, rp_hash, &key, record.cred_id);
    if (record.cred_id_len == 0 || !fpta_store_next_counter(ctap->store, &counter)) {
        return status(response, ST_OTHER);
    }
    record.seq = counter;

    uint8_t auth[AUTH_DATA_MAX], sig[SIG_MAX];
    auth_header(auth, rp_hash, FLAG_UP | FLAG_UV | FLAG_AT, counter);
    size_t off = 37;
    memcpy(auth + off, AAGUID, 16);
    off += 16;
    auth[off++] = (uint8_t)(record.cred_id_len >> 8);
    auth[off++] = (uint8_t)record.cred_id_len;
    memcpy(auth + off, record.cred_id, record.cred_id_len);
    off += record.cred_id_len;
    const size_t cose = cose_key(&key, auth + off, sizeof auth - off);
    if (cose == 0) {
        return status(response, ST_OTHER);
    }
    off += cose;

    const size_t sig_len = sign_assertion(ctap, key.blob, key.blob_len, auth, off,
                                          cbor_bytestring_handle(cdh), sig);
    if (sig_len == 0) {
        return status(response, ST_OTHER);
    }
    if (opt.rk) {
        const fpta_save_result saved = fpta_store_save_rk(ctap->store, &record);
        if (saved != FPTA_SAVE_OK) {
            return status(response, saved == FPTA_SAVE_FULL ? ST_KEY_STORE_FULL : ST_OTHER);
        }
    }

    /* "packed" self attestation: signed by the new credential key itself. */
    cbor_item_t *out = cbor_new_definite_map(3);
    cbor_item_t *stmt = cbor_new_definite_map(2);
    bool ok = out != NULL && stmt != NULL && put(stmt, text("alg"), neg(6)) &&
              put(stmt, text("sig"), blob(sig, sig_len)) &&
              put(out, u8(1), text("packed")) && put(out, u8(2), blob(auth, off)) &&
              put(out, u8(3), cbor_incref(stmt));
    if (stmt != NULL) {
        cbor_decref(&stmt);
    }
    return reply_map(out, ok, response, cap);
}

static size_t assertion_reply(fpta_ctap2 *ctap, const uint8_t *cred_id, size_t cred_len,
                              const fpta_rk *user, bool several, size_t count,
                              const uint8_t rp_hash[32],
                              const uint8_t cdh[32], uint8_t flags, uint8_t *response,
                              size_t cap)
{
    const uint8_t *tpm_blob;
    size_t tpm_blob_len;
    uint32_t counter;
    uint8_t auth[37], sig[SIG_MAX];
    if (!cred_open(ctap, rp_hash, cred_id, cred_len, &tpm_blob, &tpm_blob_len) ||
        !fpta_store_next_counter(ctap->store, &counter)) {
        return status(response, ST_OTHER);
    }
    auth_header(auth, rp_hash, flags, counter);
    const size_t sig_len = sign_assertion(ctap, tpm_blob, tpm_blob_len, auth, sizeof auth,
                                          cdh, sig);
    if (sig_len == 0) {
        return status(response, ST_OTHER);
    }

    cbor_item_t *out = cbor_new_definite_map(5);
    cbor_item_t *cred = cbor_new_definite_map(2);
    bool ok = out != NULL && cred != NULL && put(cred, text("id"), blob(cred_id, cred_len)) &&
              put(cred, text("type"), text("public-key")) &&
              put(out, u8(1), cbor_incref(cred)) && put(out, u8(2), blob(auth, sizeof auth)) &&
              put(out, u8(3), blob(sig, sig_len));
    if (cred != NULL) {
        cbor_decref(&cred);
    }
    if (ok && user != NULL) {
        /* Names are only disclosed after the user has been verified. */
        const bool names = several && (flags & FLAG_UV) != 0;
        cbor_item_t *entity = cbor_new_definite_map(3);
        ok = entity != NULL &&
             put(entity, text("id"), blob(user->user_id, user->user_id_len)) &&
             (!names || user->name[0] == '\0' || put(entity, text("name"), text(user->name))) &&
             (!names || user->display[0] == '\0' ||
              put(entity, text("displayName"), text(user->display))) &&
             put(out, u8(4), cbor_incref(entity));
        if (entity != NULL) {
            cbor_decref(&entity);
        }
    }
    if (ok && count > 1) { /* numberOfCredentials: first reply only */
        ok = put(out, u8(5), u8((uint8_t)count));
    }
    return reply_map(out, ok, response, cap);
}

static size_t get_assertion(fpta_ctap2 *ctap, uint32_t cid, const cbor_item_t *req,
                            uint8_t *response, size_t cap)
{
    const cbor_item_t *rp = map_find(req, 1, NULL);
    const cbor_item_t *cdh = map_find(req, 2, NULL);
    if (rp == NULL || cdh == NULL) {
        return status(response, ST_MISSING_PARAMETER);
    }
    char rp_id[FPTA_RP_ID_MAX + 1];
    uint8_t rp_hash[32];
    if (!read_rp_id(rp, rp_id) || !is_bytes(cdh)) {
        return status(response, ST_UNEXPECTED_TYPE);
    }
    if (cbor_bytestring_length(cdh) != 32) {
        return status(response, ST_INVALID_LENGTH);
    }
    const cbor_item_t *pin = map_find(req, 6, NULL);
    if (pin != NULL) {
        return status(response, reject_pin_auth(ctap, pin, rp_id));
    }
    options_t opt;
    uint8_t st = read_options(map_find(req, 5, NULL), &opt);
    if (st != ST_OK) {
        return status(response, st);
    }
    if (opt.rk) {
        return status(response, ST_UNSUPPORTED_OPTION);
    }
    if (!sha256(rp_id, strlen(rp_id), rp_hash)) {
        return status(response, ST_OTHER);
    }

    const cbor_item_t *allow = map_find(req, 3, NULL);
    const cbor_item_t *match = NULL;
    st = list_match(ctap, allow, rp_hash, &match);
    if (st != ST_OK) {
        return status(response, st);
    }
    const bool discover = allow == NULL || cbor_array_size(allow) == 0;
    size_t found = 0;
    if (discover) {
        found = fpta_store_find_rk(ctap->store, rp_id, ctap->pending, FPTA_RK_MAX);
    }
    if (discover ? found == 0 : match == NULL) {
        return status(response, ST_NO_CREDENTIALS);
    }

    uint8_t flags = 0;
    if (opt.up || opt.uv) {
        st = verify_user(ctap, rp_id, FPTA_OP_SIGN_IN);
        if (st != ST_OK) {
            return status(response, st);
        }
        flags = (uint8_t)(FLAG_UV | (opt.up ? FLAG_UP : 0U));
    }

    if (!discover) {
        return assertion_reply(ctap, cbor_bytestring_handle(match),
                               cbor_bytestring_length(match), NULL, false, 1, rp_hash,
                               cbor_bytestring_handle(cdh), flags, response, cap);
    }
    if (found > 1 && flags != 0) {
        ctap->pending_count = found;
        ctap->pending_index = 1;
        ctap->pending_cid = cid;
        ctap->pending_deadline = now_ms() + NEXT_ASSERTION_MS;
        ctap->pending_flags = flags;
        memcpy(ctap->pending_rp_hash, rp_hash, 32);
        memcpy(ctap->pending_cdh, cbor_bytestring_handle(cdh), 32);
    }
    return assertion_reply(ctap, ctap->pending[0].cred_id, ctap->pending[0].cred_id_len,
                           &ctap->pending[0], found > 1, flags != 0 ? found : 1, rp_hash,
                           cbor_bytestring_handle(cdh), flags, response, cap);
}

static size_t next_assertion(fpta_ctap2 *ctap, uint32_t cid, uint8_t *response, size_t cap)
{
    if (ctap->pending_index >= ctap->pending_count || cid != ctap->pending_cid ||
        now_ms() > ctap->pending_deadline) {
        ctap->pending_count = 0;
        return status(response, ST_NOT_ALLOWED);
    }
    const fpta_rk *rk = &ctap->pending[ctap->pending_index++];
    ctap->pending_deadline = now_ms() + NEXT_ASSERTION_MS;
    return assertion_reply(ctap, rk->cred_id, rk->cred_id_len, rk, true, 0,
                           ctap->pending_rp_hash, ctap->pending_cdh, ctap->pending_flags,
                           response, cap);
}

fpta_ctap2 *fpta_ctap2_new(fpta_tpm *tpm, fpta_store *store, const fpta_waiter *waiter)
{
    fpta_ctap2 *ctap = calloc(1, sizeof *ctap);
    if (ctap != NULL) {
        ctap->tpm = tpm;
        ctap->store = store;
        ctap->waiter = waiter;
    }
    return ctap;
}

void fpta_ctap2_free(fpta_ctap2 *ctap)
{
    if (ctap != NULL) {
        OPENSSL_cleanse(ctap, sizeof *ctap);
        free(ctap);
    }
}

size_t fpta_ctap2_handle(void *opaque, uint32_t cid, const uint8_t *request, size_t request_len,
                         uint8_t *response, size_t cap)
{
    fpta_ctap2 *ctap = opaque;
    if (cap < 2 || request_len == 0) {
        return status(response, ST_INVALID_LENGTH);
    }
    const uint8_t command = request[0];
    if (command != 0x08) {
        ctap->pending_count = 0;
    }
    if (command == 0x04) {
        return get_info(response, cap);
    }
    if (command == 0x08) {
        return next_assertion(ctap, cid, response, cap);
    }
    if (command == 0x07) {
        /* Remote reset would let any local client destroy every passkey. */
        return status(response, ST_NOT_ALLOWED);
    }
    if (command != 0x01 && command != 0x02) {
        return status(response, ST_INVALID_COMMAND);
    }
    size_t end = 0;
    if (!cbor_bounded(request + 1, request_len - 1, &end, 0) || end != request_len - 1) {
        return status(response, ST_INVALID_CBOR);
    }
    struct cbor_load_result result;
    cbor_item_t *req = cbor_load(request + 1, request_len - 1, &result);
    if (req == NULL || result.error.code != CBOR_ERR_NONE || result.read != request_len - 1 ||
        !is_map(req) || !no_duplicate_keys(req)) {
        if (req != NULL) {
            cbor_decref(&req);
        }
        return status(response, ST_INVALID_CBOR);
    }
    const size_t len = command == 0x01 ? make_credential(ctap, req, response, cap)
                                       : get_assertion(ctap, cid, req, response, cap);
    cbor_decref(&req);
    return len;
}
