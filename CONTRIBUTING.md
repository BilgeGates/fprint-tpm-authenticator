# Contributing

Build and run all tests (see README) before opening a pull request. Also run them
with `-DFPTA_ENABLE_SANITIZERS=ON`. Changes to parsing need a fuzz run. Run `fpta-hw-check` and `fpta-security-check` on
real hardware for changes to the broker, services or transport.

- C17, warnings are errors. Keep the broker minimal: new features belong in the
  unprivileged daemon.
- Never add a runtime way to skip fingerprint verification, including for tests.
- Say what you tested on real hardware and what you did not.

Hardware reports are welcome: distribution, reader USB ID, browser and version,
and the output of `fpta-hw-check`. Remove your user and host names. Never
attach `~/.local/share/fpta`, fingerprint data or credential IDs.
