# Architecture

## Overview

```text
 Browser / libfido2
        │  hidraw (64-byte HID reports)
        ▼
 Linux UHID ── virtual bus, FIDO usage page 0xF1D0, no USB vendor/product ID
        │  /dev/uhid
        ▼
 fpta-broker          root, socket-activated, sandboxed, no capabilities
        │  SOCK_SEQPACKET  /run/fpta-broker.sock
        ▼
 fptad                user service, sandboxed
   ├── CTAPHID        channels, fragmentation, keepalive, cancel
   ├── CTAP2          bounded CBOR parsing and authenticator commands
   ├── store          secret, signature counter, discoverable credentials
   ├── TPM signer ──► /dev/tpmrm0 (tpm2-tss ESAPI)
   ├── verifier  ──► system D-Bus ──► fprintd ──► libfprint ──► sensor
   └── prompt    ──► session D-Bus ──► fpta-prompt (window)
```

## Components

| Component | Source | Privilege | Responsibility |
| --- | --- | --- | --- |
| `fpta-broker` | `src/broker.c` | root | Creates one HID device with a fixed FIDO report descriptor and relays reports to one client |
| CTAPHID | `src/ctaphid.c` | user | Channel allocation, message reassembly and fragmentation, timeouts, `CANCEL` |
| CTAP2 | `src/ctap2.c` | user | `getInfo`, `makeCredential`, `getAssertion`, `getNextAssertion`, credential IDs |
| Store | `src/store.c` | user | Persistent state in `~/.local/share/fpta` |
| TPM signer | `src/tpm.c` | user (`tss` group) | Primary key, credential keys, ES256 signatures |
| Verifier | `src/uv_fprintd.c` | user | Fingerprint verification; drives the window |
| Window | `src/prompt/main.cpp` | user | Qt 6 confirmation window, D-Bus activated |
| Daemon | `src/main.c` | user | Event loop, keepalives, process hardening |

The CTAPHID and CTAP2 layers perform no I/O of their own, so tests can drive them
directly.

## Privilege separation

Write access to `/dev/uhid` allows creating any HID device, including a keyboard.
Granting it to the user would grant it to every program the user runs. The broker
keeps that descriptor and exposes only FIDO reports:

- one device with a fixed report descriptor, on the virtual bus, without a USB ID;
- one client at a time; further connections are closed;
- the client must be the user active on a seat (`SO_PEERCRED`, `sd_uid_get_seats`);
  the device is removed when that user is no longer active;
- reports must be exactly 64 bytes; anything else disconnects the client.

The broker holds no keys and parses no CTAP messages.

## Request flow

1. The browser sends a CTAPHID message; the broker forwards each report.
2. `fptad` reassembles it (at most 7,609 bytes, 500 ms between fragments) and parses
   the CBOR request after a structural bounds check.
3. For `makeCredential` and `getAssertion`, `fptad` calls `fprintd` with a fresh
   system-bus connection pinned to the service's unique name. Up to three attempts
   are allowed within 30 seconds. Keepalives are sent every 100 ms and `CANCEL`
   aborts the verification and releases the reader.
4. On a match the TPM signs `SHA-256(authenticatorData || clientDataHash)`.
5. The signature counter is stored durably before the response is sent.

## Confirmation window

`fpta-prompt` owns `net.fpta.Prompt` on the session bus and is started on demand
(`fpta-prompt.service`); it exits after a minute without requests.

| Method / signal | Meaning |
| --- | --- |
| `Begin(s site, u operation) → u id` | Show the window for a request |
| `SetState(u id, u state, i attempts_left)` | 0 waiting, 1 not recognized, 2 touch again, 3 recognized, 4 refused |
| `End(u id)` | Close the window |
| `Cancelled(u id)` | The user pressed Cancel or Escape |

`fptad` accepts `Cancelled` only from the connection that answered `Begin`, and
treats it as a refusal. The window cannot approve anything: a match reported by
`fprintd` is still required. If the window is unavailable, a desktop notification
is used instead. Site names are rendered as plain text.

## Keys and credential IDs

- **Primary key:** ECC P-256 storage key in the owner hierarchy, created from a fixed
  template and cached for the lifetime of the daemon.
- **Credential keys:** ECDSA P-256 children with `fixedTPM` and `fixedParent`; the
  private part is only ever held in TPM-wrapped form.
- **Credential ID:**

  ```text
  0x01 | nonce (16) | length (2) | TPM2B_PUBLIC ‖ TPM2B_PRIVATE | HMAC-SHA256 (32)
  ```

  The HMAC key is the store secret; the MAC covers the RP ID hash and all preceding
  bytes. IDs that are foreign, modified or belong to another relying party are
  rejected without using the TPM, which keeps large allow and exclude lists cheap.
- **Attestation:** `packed` self-attestation.

## State

| File | Content |
| --- | --- |
| `secret` | 32-byte HMAC key for credential IDs and records |
| `counter` | Global signature counter |
| `rk/<sha256(rp ‖ user)>` | Discoverable credential, authenticated with HMAC |
| `lock` | Exclusive lock: one daemon per directory |

Every write goes to a temporary file followed by `fsync`, `rename` and a directory
`fsync`. Incomplete or inconsistent state is never reinitialised automatically.

## Performance

The primary key is created once per daemon. Allow and exclude lists are filtered by
HMAC alone. The daemon sleeps in `poll` while idle. After hibernation or a TPM reset,
lost handles are recovered with one reconnect.

## Sandboxing

| Unit | Main restrictions | `systemd-analyze security` |
| --- | --- | --- |
| `fpta-broker.service` | no capabilities, only `/dev/uhid`, no home, no network, syscall filter | 1.2 |
| `fptad.service` | read-only system and home except `~/.local/share`, no network, syscall filter, non-dumpable | 1.1 |
| `fpta-prompt.service` | read-only system and home except `~/.cache`, Unix sockets only | – |
