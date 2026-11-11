# SentinelForge

**Local Windows event-log detection and Gmail alerting — research/portfolio release candidate**

SentinelForge is a user-scoped Windows monitoring prototype. It reads selected native Windows Event Logs, correlates repeated failed logons, stores alerts in SQLite, and submits security notifications via Gmail SMTP. It is **not antivirus, an EDR replacement, or a guarantee of protection**.

## Evidence-based status

**Project status: Windows monitoring operational. Gmail delivery verified on the developer's Windows 11 installation.**

- The one-word `SentinelForge` command works on the developer's Windows installation.
- The November 8 installation used an elevated task. This candidate migrates it to a limited task and stores the active executables under Program Files. Windows migration validation is pending.
- Status reports the last successful read and any current error for each channel.
- SQLite retains alerts and tracks notification delivery.
- SMTP failures are retained in the notification queue with retry cooldowns. Identical event 5007 messages share one eligible email per processing hour; all qualifying alerts remain in SQLite.
- On November 8, 2026, the installed background agent submitted synthetic self-test alert #717 through Gmail SMTP. The recipient confirmed it arrived in the inbox.
- The application has not yet passed clean-install testing on another Windows computer.

**Security limitations:** SentinelForge detects selected event patterns. It does not block attacks, replace Microsoft Defender, or guarantee detection of every threat.
## Architecture

```text
Windows Event Logs (Security / System / Defender)
    → RecordID-aware PowerShell collector
    → Rule engine and burst correlation
    → SQLite alerts, cursor, notification outbox
    → Background task (Windows logon trigger)
    → Windows Credential Manager → Gmail SMTP/TLS
                           ↘ monitor.log
```

**Integrity model:** The log collector uses `EventRecordID` cursor filtering *inside the Windows query*, then reads oldest-first to avoid skipping unread records when the result limit is reached. Records are persisted to SQLite. The notification baseline suppresses historic alerts without deleting them. A separate notification state table tracks email successes and failures.

## Windows installation

Build on a supported Windows machine with Python and PyInstaller using `build-windows.ps1`. Extract `dist/SentinelForge-Windows.zip` (both executables) and run `SentinelForge.exe setup` from the extracted folder. The initial setup asks for a recipient address, Gmail sender, and a **Gmail App Password** (stored in the current Windows user's Credential Manager). It registers a per-user Scheduled Task to start the agent at login.

A fully automatic one-word system-wide command on a **fresh computer** is a separate installer/PATH task; do not claim that extracting two executables alone registers a shell command. For an existing installation that has `SentinelForge.cmd` in PATH, the one-word command is supported.

## Commands

| Command | Behavior |
|---|---|
| `SentinelForge` / `SentinelForge status` | Shows installed status and email outbox counts |
| `SentinelForge self-test` | Queues a clearly labelled synthetic alert; waits for **the installed background agent** to mark SMTP delivery successful; **verify inbox arrival separately** |
| `SentinelForge scan` | Collects selected native events once and attempts queued deliveries |
| `SentinelForge demo` | Generates a synthetic failed-logon burst in memory, without sending mail |
| `SentinelForge start` / `stop` | Manages the scheduled task |
| `SentinelForge uninstall` | Removes the scheduled task; preserves history and saved credentials |

For an existing installation, follow [the build, migration and verification steps](HARDENING.md).
After migration, use the protected CLI beside the scheduled agent for status and self-test.

## Detection coverage

- Security: 4625 repeated failed sign-ins (5 in 10 minutes, grouped per log channel), 4720 account creation, 4728 and 4732 security-group membership, 4697 service installation, 1102 audit log cleared, 4719 audit-policy changes.
- System: 7045 service installation.
- Windows Defender Operational: 1116 detection, 1117 remediation, 1118 remediation failure, 5007 selected configuration changes, 5001 real-time protection disabled, 5013 tamper protection blocked a change.
- 4624 successful sign-ins are collected but not alerted on by default due to high noise.

**Limitations:** Not all Windows editions expose all events to a standard user. No ETW kernel sensor, malware sandbox, memory scanner, behavioral model, tamper protection, or threat prevention is included. Failed logon bursts are aggregated per channel, not by username or source IP. SQLite stores correlation history and the channel cursor across collector restarts. Detection depends on Windows auditing, log retention, adequate privileges, and event volume. `0 alerts` means no configured rule fired, **not that the machine is clean**.

## Privacy and credentials

Event evidence remains locally in `%USERPROFILE%\SentinelForgeData\events.sqlite3`. Logs are in `monitor.log`. The current email body includes the rule, title, severity, and time, **not the full event evidence**. Gmail SMTP delivery necessarily transmits notification contents to Google and the recipient. Avoid using a personal Gmail identity in public code or demos. Never publish the SQLite database, Credential Manager secrets, or local config files.

## Verification

Run `python -m unittest discover -s tests -v`. On Windows verify background task startup after logon, read permissions for all three channels, a benign audit event that is expected to fire a rule, and `SentinelForge self-test` followed by checking the recipient inbox. The `self-test` creates a persistent clearly labelled test alert; it does not fake a Security Event Log entry, simulate an intrusion, or prove event collection works.

See `docs/THREAT_MODEL.md`, `docs/RESEARCH_PROTOCOL.md`, `docs/RELEASE_CHECKLIST.md` for test design and disclosure boundaries.

## Faculty pilot report

From the source checkout, run
`python -m sentinelforge pilot-report --from-date 2026-11-01 --to-date 2026-11-11`
with the desired inclusive UTC dates. Open the printed HTML path in a browser
and print to PDF for review. The report reads local SQLite in one read-only
transaction. It summarizes stored alerts, self-tests, latest email states and
the most recent check of each configured channel. Raw evidence and error messages
stay out of the report. The evidence CSV is a separate investigation export.
