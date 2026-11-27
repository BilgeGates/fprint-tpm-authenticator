# Changelog

## 0.2.0 - 2026-11-27

- Confirmation window `fpta-prompt` (Qt 6): names the site, shows the sensor's
  progress and attempts left, and cancels the request. A desktop notification
  remains the fallback.
- The CTAPHID device version follows the release version.

## 0.1.0 - 2026-11-25

- CTAPHID and CTAP 2.0 authenticator with TPM 2.0 ES256 keys
- Fingerprint verification through fprintd with a desktop notification
- Privileged broker that exposes only a FIDO HID device
- Discoverable credentials (passkeys)
- Unit, end-to-end (libfido2 + swtpm), fprintd client and fuzz tests
- Virtual HID device on the virtual bus, claiming no USB vendor/product ID
