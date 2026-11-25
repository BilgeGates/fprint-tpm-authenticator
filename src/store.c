/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#include "fpta/store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define SECRET_LEN 32U
#define MAC_LEN 32U
#define RK_HEADER 12U /* "FPR1" seq(4) rp user name display lengths */
#define RK_FILE_MAX (RK_HEADER + FPTA_RP_ID_MAX + FPTA_USER_ID_MAX + \
                     2 * FPTA_NAME_MAX + FPTA_CRED_ID_MAX + MAC_LEN)

struct fpta_store {
    int dir;
    int rk_dir;
    int lock;
    uint32_t counter;
    uint8_t secret[SECRET_LEN];
};

static bool write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0) {
        const ssize_t n = write(fd, data, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

static bool write_atomic(int dir, const char *name, const uint8_t *data, size_t len)
{
    char tmp[96];
    if (snprintf(tmp, sizeof tmp, ".%s.tmp", name) >= (int)sizeof tmp) {
        return false;
    }
    (void)unlinkat(dir, tmp, 0);
    const int fd = openat(dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    bool ok = write_all(fd, data, len) && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    ok = ok && renameat(dir, tmp, dir, name) == 0 && fsync(dir) == 0;
    if (!ok) {
        (void)unlinkat(dir, tmp, 0);
    }
    return ok;
}

/* Returns the file size, -1 if absent, -2 on any other problem. */
static ssize_t read_file(int dir, const char *name, uint8_t *out, size_t cap)
{
    const int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return errno == ENOENT ? -1 : -2;
    }
    size_t got = 0;
    ssize_t n = 0;
    while (got < cap && (n = read(fd, out + got, cap - got)) > 0) {
        got += (size_t)n;
    }
    uint8_t extra;
    const bool bad = n < 0 || (got == cap && read(fd, &extra, 1) != 0);
    (void)close(fd);
    return bad ? -2 : (ssize_t)got;
}

static int open_private_dir(int parent, const char *path)
{
    if (mkdirat(parent, path, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    const int fd = openat(parent, path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 077) != 0)) {
        fprintf(stderr, "fpta: %s must be owned by you with mode 0700\n", path);
        (void)close(fd);
        return -1;
    }
    return fd;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static bool rk_directory_empty(int rk_dir)
{
    const int fd = openat(rk_dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (dir == NULL) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return false;
    }
    bool empty = true;
    const struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            empty = false;
        }
    }
    (void)closedir(dir);
    return empty;
}

static bool load_state(fpta_store *store)
{
    uint8_t counter[4];
    const ssize_t secret_len = read_file(store->dir, "secret", store->secret, SECRET_LEN);
    const ssize_t counter_len = read_file(store->dir, "counter", counter, sizeof counter);

    if (secret_len == (ssize_t)SECRET_LEN && counter_len == 4) {
        store->counter = get32(counter);
        return true;
    }
    /* Initialise only a pristine directory. The counter is written first so an
     * interrupted initialisation leaves a state that can be redone safely. */
    if (secret_len == -1 && rk_directory_empty(store->rk_dir) &&
        (counter_len == -1 || (counter_len == 4 && get32(counter) == 0))) {
        put32(counter, 0);
        store->counter = 0;
        return RAND_bytes(store->secret, SECRET_LEN) == 1 &&
               write_atomic(store->dir, "counter", counter, sizeof counter) &&
               write_atomic(store->dir, "secret", store->secret, SECRET_LEN);
    }
    fprintf(stderr, "fpta: state is incomplete or corrupt; refusing to overwrite it\n");
    return false;
}

fpta_store *fpta_store_open(const char *path)
{
    fpta_store *store = calloc(1, sizeof *store);
    if (store == NULL) {
        return NULL;
    }
    store->rk_dir = store->lock = -1;
    store->dir = open_private_dir(AT_FDCWD, path);
    if (store->dir >= 0) {
        store->lock = openat(store->dir, "lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    if (store->lock >= 0 && flock(store->lock, LOCK_EX | LOCK_NB) == 0) {
        store->rk_dir = open_private_dir(store->dir, "rk");
    }
    if (store->rk_dir < 0 || !load_state(store)) {
        fpta_store_close(store);
        return NULL;
    }
    return store;
}

void fpta_store_close(fpta_store *store)
{
    if (store == NULL) {
        return;
    }
    const int fds[] = {store->rk_dir, store->lock, store->dir};
    for (size_t i = 0; i < 3; i++) {
        if (fds[i] >= 0) {
            (void)close(fds[i]);
        }
    }
    OPENSSL_cleanse(store, sizeof *store);
    free(store);
}

const uint8_t *fpta_store_secret(const fpta_store *store)
{
    return store->secret;
}

bool fpta_store_next_counter(fpta_store *store, uint32_t *value)
{
    if (store->counter == UINT32_MAX) {
        return false;
    }
    uint8_t raw[4];
    put32(raw, store->counter + 1);
    if (!write_atomic(store->dir, "counter", raw, sizeof raw)) {
        return false;
    }
    *value = ++store->counter;
    return true;
}

static bool rk_mac(const fpta_store *store, const uint8_t *data, size_t len, uint8_t mac[MAC_LEN])
{
    unsigned int out = 0;
    return HMAC(EVP_sha256(), store->secret, SECRET_LEN, data, len, mac, &out) != NULL &&
           out == MAC_LEN;
}

static bool rk_file_name(const char *rp_id, const uint8_t *user_id, size_t user_len,
                         char name[65])
{
    uint8_t input[FPTA_RP_ID_MAX + 1 + FPTA_USER_ID_MAX];
    uint8_t hash[32];
    const size_t rp_len = strlen(rp_id);
    memcpy(input, rp_id, rp_len + 1);
    memcpy(input + rp_len + 1, user_id, user_len);
    if (EVP_Digest(input, rp_len + 1 + user_len, hash, NULL, EVP_sha256(), NULL) != 1) {
        return false;
    }
    for (size_t i = 0; i < sizeof hash; i++) {
        (void)snprintf(name + 2 * i, 3, "%02x", hash[i]);
    }
    return true;
}

/* header | rp_id | user_id | name | display | credential id (rest) | HMAC */
static bool rk_parse(const fpta_store *store, const uint8_t *data, size_t len, fpta_rk *rk)
{
    uint8_t mac[MAC_LEN];
    if (len < RK_HEADER + MAC_LEN || memcmp(data, "FPR1", 4) != 0 ||
        !rk_mac(store, data, len - MAC_LEN, mac) ||
        CRYPTO_memcmp(mac, data + len - MAC_LEN, MAC_LEN) != 0) {
        return false;
    }
    const size_t rp = data[8], user = data[9], name = data[10];
    const size_t display = data[11];
    const size_t cred_len = len - MAC_LEN - RK_HEADER - rp - user - name - display;
    if (rp > FPTA_RP_ID_MAX || user == 0 || user > FPTA_USER_ID_MAX || name > FPTA_NAME_MAX ||
        display > FPTA_NAME_MAX || len < RK_HEADER + rp + user + name + display + MAC_LEN ||
        cred_len == 0 || cred_len > FPTA_CRED_ID_MAX) {
        return false;
    }
    memset(rk, 0, sizeof *rk);
    rk->seq = get32(data + 4);
    const uint8_t *p = data + RK_HEADER;
    memcpy(rk->rp_id, p, rp);
    p += rp;
    memcpy(rk->user_id, p, user);
    rk->user_id_len = user;
    p += user;
    memcpy(rk->name, p, name);
    p += name;
    memcpy(rk->display, p, display);
    p += display;
    memcpy(rk->cred_id, p, cred_len);
    rk->cred_id_len = cred_len;
    return true;
}

static size_t rk_encode(const fpta_store *store, const fpta_rk *rk, uint8_t out[RK_FILE_MAX])
{
    const size_t rp = strlen(rk->rp_id), name = strlen(rk->name), display = strlen(rk->display);
    memcpy(out, "FPR1", 4);
    put32(out + 4, rk->seq);
    out[8] = (uint8_t)rp;
    out[9] = (uint8_t)rk->user_id_len;
    out[10] = (uint8_t)name;
    out[11] = (uint8_t)display;
    size_t off = RK_HEADER;
    memcpy(out + off, rk->rp_id, rp);
    off += rp;
    memcpy(out + off, rk->user_id, rk->user_id_len);
    off += rk->user_id_len;
    memcpy(out + off, rk->name, name);
    off += name;
    memcpy(out + off, rk->display, display);
    off += display;
    memcpy(out + off, rk->cred_id, rk->cred_id_len);
    off += rk->cred_id_len;
    return rk_mac(store, out, off, out + off) ? off + MAC_LEN : 0;
}

/* Calls visit for every intact entry; returns the number of files seen. */
static size_t rk_scan(fpta_store *store, void (*visit)(const fpta_rk *, void *), void *ctx)
{
    const int fd = openat(store->rk_dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd >= 0 ? fdopendir(fd) : NULL;
    if (dir == NULL) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return SIZE_MAX;
    }
    size_t files = 0;
    const struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        files++;
        if (visit == NULL) {
            continue;
        }
        uint8_t data[RK_FILE_MAX];
        fpta_rk rk;
        const ssize_t len = read_file(store->rk_dir, entry->d_name, data, sizeof data);
        if (len > 0 && rk_parse(store, data, (size_t)len, &rk)) {
            visit(&rk, ctx);
        } else {
            fprintf(stderr, "fpta: ignoring damaged passkey record %s\n", entry->d_name);
        }
    }
    (void)closedir(dir);
    return files;
}

fpta_save_result fpta_store_save_rk(fpta_store *store, const fpta_rk *rk)
{
    char name[65];
    uint8_t data[RK_FILE_MAX];
    if (rk->user_id_len == 0 || rk->user_id_len > FPTA_USER_ID_MAX || rk->cred_id_len == 0 ||
        rk->cred_id_len > FPTA_CRED_ID_MAX ||
        !rk_file_name(rk->rp_id, rk->user_id, rk->user_id_len, name)) {
        return FPTA_SAVE_ERROR;
    }
    if (faccessat(store->rk_dir, name, F_OK, 0) != 0) {
        const size_t count = rk_scan(store, NULL, NULL);
        if (count == SIZE_MAX) {
            return FPTA_SAVE_ERROR;
        }
        if (count >= FPTA_RK_MAX) {
            return FPTA_SAVE_FULL;
        }
    }
    const size_t len = rk_encode(store, rk, data);
    return len > 0 && write_atomic(store->rk_dir, name, data, len) ? FPTA_SAVE_OK
                                                                   : FPTA_SAVE_ERROR;
}

typedef struct {
    const char *rp_id;
    fpta_rk *out;
    size_t cap;
    size_t count;
} find_ctx;

static void find_visit(const fpta_rk *rk, void *opaque)
{
    find_ctx *ctx = opaque;
    if (strcmp(rk->rp_id, ctx->rp_id) == 0 && ctx->count < ctx->cap) {
        ctx->out[ctx->count++] = *rk;
    }
}

static int newest_first(const void *a, const void *b)
{
    const uint32_t x = ((const fpta_rk *)a)->seq, y = ((const fpta_rk *)b)->seq;
    return x < y ? 1 : x > y ? -1 : 0;
}

size_t fpta_store_find_rk(fpta_store *store, const char *rp_id, fpta_rk *out, size_t cap)
{
    find_ctx ctx = {.rp_id = rp_id, .out = out, .cap = cap};
    (void)rk_scan(store, find_visit, &ctx);
    qsort(out, ctx.count, sizeof *out, newest_first);
    return ctx.count;
}
