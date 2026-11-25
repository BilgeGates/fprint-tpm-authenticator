# Testing

## Running the tests

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Requirements: `libfido2`, `swtpm` and `dbus`. No test touches real hardware or the
system bus.

With sanitizers:

```sh
cmake -S . -B build-asan -DFPTA_ENABLE_SANITIZERS=ON
cmake --build build-asan && ctest --test-dir build-asan
```

## Test suites

| Test | Scope |
| --- | --- |
| `ctaphid` | Maximum-size fragmentation, invalid sequence, channel and length, busy channel, timeout, cancellation during a request |
| `e2e_libfido2_swtpm` | The daemon with libfido2 as an independent client and `swtpm` as the TPM. libfido2 verifies every signature. Covers RP binding, modified IDs, exclude lists, silent assertions, passkeys, denial, cancellation, restart persistence, the counter and hostile CBOR |
| `fprintd_client` | The real D-Bus client against a scripted `fprintd` on a private bus: match, retry, wrong finger, busy reader, cancellation and reader error, and that the reader is always released |

In the end-to-end test the fingerprint step is scripted by `tests/fake_uv.c`, which is
linked only into the `fptad-test` binary. That binary is never installed and the
daemon has no option to skip verification.

## Fuzzing

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang -DFPTA_ENABLE_FUZZING=ON -DBUILD_TESTING=OFF
cmake --build build-fuzz --target fuzz_ctap
./build-fuzz/fuzz_ctap -max_len=4096 -max_total_time=600
```

The target feeds both raw CTAPHID reports and CTAP2 requests, with the TPM and the
verifier stubbed. Fuzzing found that libcbor allocates containers from their
declared size; a structural bounds check now runs before parsing, with a regression
test.

## Static analysis

`gcc -fanalyzer` and the Clang static analyzer (core, unix, security and bounds
checkers) report no findings. Binaries are built as PIE with full RELRO, a
non-executable stack and the stack protector.

## On real hardware

```sh
tools/hw-check.sh         # registration, sign-in and wrong-finger rejection
tools/security-check.sh   # permissions, isolation, broker takeover, hostile input
```

`security-check.sh` sends 20,000 hostile HID reports to the live device and checks
that the daemon keeps working.

## Results for 0.1.0

| Check | Result |
| --- | --- |
| Automated tests, with and without sanitizers | Passed |
| Fuzzing, about 12 million executions | No findings |
| `tools/hw-check.sh` | 13 / 13 |
| `tools/security-check.sh` | 17 / 17 |
| Brave on webauthn.io: registration, sign-in, cancellation, wrong finger | Passed |

Hardware: HP ProBook 450 G8, ELAN `04f3:0c5e`, Intel TPM 2.0, Arch Linux.

Not yet tested: Firefox, Chromium, Google Chrome, Snap and Flatpak browsers, other
distributions, suspend and resume, and concurrent use with the lock screen.
