# Security

## Reporting a vulnerability

Report vulnerabilities privately with **Report a vulnerability** on the repository's
Security tab. Please do not open a public issue. Only the latest release is supported.

## Security model

fpta protects against:

- copying keys off the machine: keys are created in the TPM and cannot be exported;
- phishing: each signature is bound to one relying party ID;
- remote websites: a user-verified signature requires a fingerprint match at the
  time of the request;
- unprivileged access to `/dev/uhid`: only the broker can create the device, and it
  creates only a FIDO device;
- malformed requests: CBOR sizes, depth and duplicate keys are checked before parsing.

## Limitations

- **The TPM does not enforce the fingerprint check.** `fptad` decides in software and
  the keys have empty authorization. Malware running as your user, with `tss`
  access, can sign without a fingerprint.
- **Use full-disk encryption.** Someone who boots another system on the same laptop
  can read `~/.local/share/fpta` and use the TPM.
- Root or a compromised kernel controls everything, including `fprintd` results.
- The sensor's false-accept rate and spoof resistance depend on the reader and
  `libfprint`, not on this project.
- Desktop notifications can be imitated by local programs. The browser dialog also
  names the site.
- Another program of the same user can connect to the broker before `fptad` and
  block the security key.
- Attestation is "packed" self-attestation, so sites that require certified
  authenticators reject it.
- Requests with `up=false` are answered without a fingerprint, with the presence and
  verification flags cleared, as CTAP2 allows.
- A TPM clear, a mainboard replacement or deleting the state directory destroys all
  credentials.

This project has not had an independent security audit.
