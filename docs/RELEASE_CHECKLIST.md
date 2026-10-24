# Release-readiness gate

- [x] Document detection rules and unsupported threats.
- [x] Unit tests for baseline, outbox, detector, Windows query shape, and self-test result handling.
- [x] Add a self-test that uses the installed background agent's outbox processing.
- [x] Do not transmit raw event evidence in email body.
- [ ] Build both executables **on Windows** from clean source.
- [ ] Confirm PyInstaller one-file parent/child process model and that only one logical scanner runs.
- [ ] Fresh Windows VM: setup, PATH/one-word command expectations, startup, crash recovery.
- [ ] Fresh Windows VM: real Windows event → SQLite alert → Gmail SMTP → inbox.
- [ ] Fresh Windows VM: `SentinelForge self-test` succeeds and message arrives.
- [ ] Test under lost event-channel access, log cleared and reset cursor scenarios.
- [ ] Inspect binaries for credentials and scan release artifacts.
- [ ] Supply reproducible version, hashes, signed tag/installer as appropriate.
- [ ] Conduct event-volume/performance measurements in research protocol.

**Do not claim "production-ready," "guaranteed protection," or "master's research validated" while unchecked items remain.**
