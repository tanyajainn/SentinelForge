# SentinelForge — Windows Release Candidate

**Status:** Release candidate, pending independent Windows VM acceptance testing  
**Source branch:** `feature/detection-v2`  
**Build date:** 2026-11-20  
**Package:** `SentinelForge-Windows.zip`

## Scope

SentinelForge is a local Windows Event Log monitoring prototype. It reads selected Security, System and Microsoft Defender Operational events, evaluates configured rules and correlations, stores alerts and cursors in SQLite, and submits eligible notifications through Gmail SMTP. It is an advisory monitoring tool, **not** an antivirus or EDR replacement.

## Release contents

- `SentinelForge.exe` — command-line setup, status, scan, self-test and reporting commands.
- `SentinelForgeAgent.exe` — background event collection and notification processing.

The ZIP archive passed Python `zipfile.testzip()` and contains exactly these two executables. The build script's CLI help and synthetic demo smoke tests also completed successfully on the developer's Windows machine.

## SHA-256 verification

```text
File: SentinelForge-Windows.zip
SHA256: 4BE58DB366B7F132A25DC8B18561D9BF5DEDCF626608D5CDB5BF6DC5292A34DE
```

Verify a downloaded copy in PowerShell:

```powershell
(Get-FileHash .\SentinelForge-Windows.zip -Algorithm SHA256).Hash
```

The printed value must match the above. This checksum applies **only to the exact ZIP built on 2026-11-20**. Rebuilding, recompressing or editing the ZIP requires a new checksum.

## Evidence already obtained

- The project's complete Python regression suite passed with **108 tests** on the development machine after adding opt-in v3 research tests. This does **not** mean v3 is included in the v2 release.
- The installed Windows agent was observed running under Task Scheduler. Two `SentinelForgeAgent.exe` processes formed a parent-child chain, consistent with PyInstaller one-file mode.
- Security, System and Microsoft Defender Operational channels each reported a successful event read on the development installation on 2026-11-20.
- The development installation's notification state reported `email new undelivered: 0`; this is **not** an inbox-delivery measurement for a clean installation.
- A faculty pilot HTML report was generated for 2026-11-01 through 2026-11-20.
- Synthetic contextual and adversarial evaluation results are documented separately. **None of their precision, recall or F1 scores estimate real-world accuracy.**

## Known limitations

- Failed-logon bursts may be triggered by benign password mistakes, shared gateways or stale service credentials. Slow and distributed activity can be missed.
- Some Windows event channels and event IDs require particular audit policies and permissions.
- No automatic attack blocking is enabled. An alert indicates a configured rule fired, not that compromise is confirmed.
- The experimental contextual v3 engine is retained on the separate `research/contextual-v3` branch and is not part of this candidate.
- Clean installation, event-to-alert integration, restart recovery and email arrival have **not yet been verified on an independent Windows VM**.

## Final acceptance checklist — disposable Windows VM

- [ ] Extract the ZIP and verify its SHA-256 checksum.
- [ ] Run initial setup as a non-administrator, using a disposable test mailbox and credentials.
- [ ] Confirm the scheduled task runs with limited user privileges after sign-in and restart.
- [ ] Confirm fresh successful Security, System and Defender Operational reads (or record permissions-related failures transparently).
- [ ] Generate an authorized, benign Windows audit event and match EventRecordID to a stored SQLite alert.
- [ ] Run the self-test, verify the agent marks SMTP submission and separately confirm inbox arrival.
- [ ] Test restart and a temporary SMTP/network outage without losing stored evidence or duplicating notifications unexpectedly.
- [ ] Check release files for secrets and scan binaries.
- [ ] Record observed environment, results, exact source commit, ZIP checksum and any failures.
- [ ] Only after acceptance, publish a versioned GitHub release and tag the tested source commit.

## Installation note

For first-time setup, extract **both executables** together and run `SentinelForge.exe setup` from an ordinary PowerShell session. Use an isolated test VM for initial release acceptance. The executable package does not itself establish a global one-word `SentinelForge` command on a fresh machine. See `README.md`, `HARDENING.md` and `docs/RELEASE_CHECKLIST.md` for documented setup and verification details.
