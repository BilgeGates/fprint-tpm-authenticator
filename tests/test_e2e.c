/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 The fprint-tpm-authenticator authors */
#undef NDEBUG
#include <assert.h>
#include <fido.h>
#include <fido/es256.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr, want)                                                            \
    do {                                                                             \
        const int got_ = (expr);                                                     \
        if (got_ != (want)) {                                                        \
            fprintf(stderr, "line %d: %s = %s, expected %s\n", __LINE__, #expr,      \
                    fido_strerr(got_), fido_strerr(want));                           \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

static int channel = -1;
static pid_t daemon_pid;
static fido_dev_t *dev;

static void *io_open(const char *path) { (void)path; return &channel; }
static void io_close(void *handle) { (void)handle; }

static int io_read(void *handle, unsigned char *buf, size_t len, int ms)
{
    (void)handle;
    struct pollfd p = {.fd = channel, .events = POLLIN};
    int ready;
    do {
        ready = poll(&p, 1, ms < 0 ? 10000 : ms);
    } while (ready < 0);
    return ready == 1 ? (int)recv(channel, buf, len, 0) : -1;
}

static int io_write(void *handle, const unsigned char *buf, size_t len)
{
    (void)handle;
    if (len != 65 || send(channel, buf + 1, 64, 0) != 64) {
        return -1;
    }
    return (int)len;
}

static void start(const char *daemon, const char *state, const char *tcti)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0);
    daemon_pid = fork();
    assert(daemon_pid >= 0);
    if (daemon_pid == 0) {
        (void)close(pair[0]);
        assert(dup2(pair[1], 3) == 3);
        execl(daemon, daemon, "--fd", "3", "--state-dir", state, "--tcti", tcti, (char *)NULL);
        _exit(127);
    }
    (void)close(pair[1]);
    channel = pair[0];
    const fido_dev_io_t io = {io_open, io_close, io_read, io_write};
    dev = fido_dev_new();
    assert(dev != NULL);
    CHECK(fido_dev_set_io_functions(dev, &io), FIDO_OK);
    CHECK(fido_dev_open(dev, "fpta-test"), FIDO_OK);
}

static void stop(void)
{
    CHECK(fido_dev_close(dev), FIDO_OK);
    fido_dev_free(&dev);
    (void)close(channel);
    assert(waitpid(daemon_pid, NULL, 0) == daemon_pid);
}

static double elapsed_ms(const struct timespec *from)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - from->tv_sec) * 1e3 +
           (double)(now.tv_nsec - from->tv_nsec) / 1e6;
}

static const unsigned char CDH[32] = {0x5a, 1, 2, 3};

static int make(const char *rp, const char *user, bool resident, const fido_cred_t *exclude,
                fido_cred_t **out)
{
    fido_cred_t *c = fido_cred_new();
    assert(c != NULL);
    CHECK(fido_cred_set_type(c, COSE_ES256), FIDO_OK);
    CHECK(fido_cred_set_clientdata_hash(c, CDH, sizeof CDH), FIDO_OK);
    CHECK(fido_cred_set_rp(c, rp, "Test RP"), FIDO_OK);
    CHECK(fido_cred_set_user(c, (const unsigned char *)user, strlen(user), user, "Display", NULL),
          FIDO_OK);
    CHECK(fido_cred_set_rk(c, resident ? FIDO_OPT_TRUE : FIDO_OPT_OMIT), FIDO_OK);
    if (exclude != NULL) {
        CHECK(fido_cred_exclude(c, fido_cred_id_ptr(exclude), fido_cred_id_len(exclude)),
              FIDO_OK);
    }
    const int result = fido_dev_make_cred(dev, c, NULL);
    if (out != NULL) {
        *out = c;
    } else {
        fido_cred_free(&c);
    }
    return result;
}

static fido_assert_t *new_assert(const char *rp, const unsigned char *id, size_t id_len)
{
    fido_assert_t *a = fido_assert_new();
    assert(a != NULL);
    CHECK(fido_assert_set_clientdata_hash(a, CDH, sizeof CDH), FIDO_OK);
    CHECK(fido_assert_set_rp(a, rp), FIDO_OK);
    if (id != NULL) {
        CHECK(fido_assert_allow_cred(a, id, id_len), FIDO_OK);
    }
    return a;
}

static void verify(const fido_assert_t *a, size_t index, const fido_cred_t *cred)
{
    es256_pk_t *pk = es256_pk_new();
    assert(pk != NULL);
    CHECK(es256_pk_from_ptr(pk, fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred)),
          FIDO_OK);
    CHECK(fido_assert_verify(a, index, COSE_ES256, pk), FIDO_OK);
    es256_pk_free(&pk);
}

static uint32_t sign_with(const char *rp, const fido_cred_t *cred)
{
    fido_assert_t *a = new_assert(rp, fido_cred_id_ptr(cred), fido_cred_id_len(cred));
    CHECK(fido_dev_get_assert(dev, a, NULL), FIDO_OK);
    verify(a, 0, cred);
    assert((fido_assert_flags(a, 0) & 0x05) == 0x05);
    const uint32_t counter = fido_assert_sigcount(a, 0);
    fido_assert_free(&a);
    return counter;
}

static void expect_assert(const char *rp, const unsigned char *id, size_t len, int want)
{
    fido_assert_t *a = new_assert(rp, id, len);
    CHECK(fido_dev_get_assert(dev, a, NULL), want);
    fido_assert_free(&a);
}

static void on_alarm(int number)
{
    (void)number;
    (void)fido_dev_cancel(dev);
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    fido_init(0);
    start(argv[1], argv[2], argv[3]);

    assert(fido_dev_is_fido2(dev));
    fido_cbor_info_t *info = fido_cbor_info_new();
    CHECK(fido_dev_get_cbor_info(dev, info), FIDO_OK);
    assert(strcmp(fido_cbor_info_versions_ptr(info)[0], "FIDO_2_0") == 0);
    fido_cbor_info_free(&info);
    assert(fido_dev_has_uv(dev) && !fido_dev_has_pin(dev));

    struct timespec t0;
    (void)clock_gettime(CLOCK_MONOTONIC, &t0);
    fido_cred_t *plain;
    CHECK(make("example.com", "alice", false, NULL, &plain), FIDO_OK);
    printf("makeCredential: %.1f ms (software TPM)\n", elapsed_ms(&t0));
    CHECK(fido_cred_verify_self(plain), FIDO_OK);
    assert((fido_cred_flags(plain) & 0x45) == 0x45);

    (void)clock_gettime(CLOCK_MONOTONIC, &t0);
    const uint32_t first = sign_with("example.com", plain);
    printf("getAssertion:   %.1f ms (software TPM)\n", elapsed_ms(&t0));
    const uint32_t second = sign_with("example.com", plain);
    assert(second > first);

    expect_assert("evil.example", fido_cred_id_ptr(plain), fido_cred_id_len(plain),
                  FIDO_ERR_NO_CREDENTIALS);
    unsigned char forged[600];
    const size_t id_len = fido_cred_id_len(plain);
    assert(id_len <= sizeof forged);
    const size_t positions[] = {0, 1, 18, 40, id_len - 40, id_len - 1};
    for (size_t i = 0; i < sizeof positions / sizeof *positions; i++) {
        memcpy(forged, fido_cred_id_ptr(plain), id_len);
        forged[positions[i]] ^= 1;
        expect_assert("example.com", forged, id_len, FIDO_ERR_NO_CREDENTIALS);
    }
    CHECK(make("example.com", "alice", false, plain, NULL), FIDO_ERR_CREDENTIAL_EXCLUDED);

    fido_assert_t *quiet = new_assert("example.com", fido_cred_id_ptr(plain), id_len);
    CHECK(fido_assert_set_up(quiet, FIDO_OPT_FALSE), FIDO_OK);
    CHECK(fido_dev_get_assert(dev, quiet, NULL), FIDO_OK);
    assert((fido_assert_flags(quiet, 0) & 0x05) == 0);
    fido_assert_free(&quiet);

    fido_cred_t *bob, *carol, *bob2;
    CHECK(make("passkeys.example", "bob", true, NULL, &bob), FIDO_OK);
    CHECK(make("passkeys.example", "carol", true, NULL, &carol), FIDO_OK);
    CHECK(make("passkeys.example", "bob", true, NULL, &bob2), FIDO_OK);
    fido_assert_t *found = new_assert("passkeys.example", NULL, 0);
    CHECK(fido_dev_get_assert(dev, found, NULL), FIDO_OK);
    assert(fido_assert_count(found) == 2);
    verify(found, 0, bob2);
    verify(found, 1, carol);
    assert(fido_assert_user_id_len(found, 0) == 3 &&
           memcmp(fido_assert_user_id_ptr(found, 0), "bob", 3) == 0);
    assert(strcmp(fido_assert_user_name(found, 1), "carol") == 0);
    fido_assert_free(&found);
    expect_assert("nobody.example", NULL, 0, FIDO_ERR_NO_CREDENTIALS);

    CHECK(make("deny.example", "x", false, NULL, NULL), FIDO_ERR_OPERATION_DENIED);
    const struct sigaction action = {.sa_handler = on_alarm};
    assert(sigaction(SIGALRM, &action, NULL) == 0);
    alarm(1);
    CHECK(make("wait.example", "x", false, NULL, NULL), FIDO_ERR_KEEPALIVE_CANCEL);
    CHECK(fido_dev_reset(dev), FIDO_ERR_NOT_ALLOWED);
    const struct { unsigned char bytes[12]; size_t len; } hostile[] = {
        {{0x02, 0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 10},
        {{0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}, 10},
        {{0x02, 0x9f, 0xff}, 3},
        {{0x02, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00}, 12},
        {{0x02, 0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62}, 8}};
    for (size_t i = 0; i < sizeof hostile / sizeof *hostile; i++) {
        unsigned char report[65] = {0, 0, 0, 0, 0, 0x90, 0, (unsigned char)hostile[i].len};
        unsigned char reply[64];
        unsigned char init[65] = {0, 0xff, 0xff, 0xff, 0xff, 0x86, 0, 8};
        assert(io_write(&channel, init, sizeof init) == 65);
        assert(io_read(&channel, reply, sizeof reply, 2000) == 64);
        memcpy(report + 1, reply + 15, 4);
        memcpy(report + 8, hostile[i].bytes, hostile[i].len);
        assert(io_write(&channel, report, sizeof report) == 65);
        assert(io_read(&channel, reply, sizeof reply, 2000) == 64);
        assert(reply[4] == 0x90 && reply[6] == 1 && reply[7] == 0x12);
    }
    const uint32_t before_restart = sign_with("example.com", plain);

    stop();
    start(argv[1], argv[2], argv[3]);
    assert(sign_with("example.com", plain) > before_restart);
    sign_with("passkeys.example", carol);
    for (int i = 0; i < 25; i++) {
        sign_with("example.com", plain);
    }
    stop();

    fido_cred_free(&plain);
    fido_cred_free(&bob);
    fido_cred_free(&bob2);
    fido_cred_free(&carol);
    puts("end-to-end (libfido2 + TPM): all checks passed");
    return 0;
}
