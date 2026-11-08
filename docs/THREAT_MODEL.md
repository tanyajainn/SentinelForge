# SentinelForge threat model

## Objective

Assess whether a non-administrative, user-scoped monitor can detect selected high-signal Windows events and notify its owner without persistent terminal interaction.

## Trust boundaries

1. **Windows Event Log** is an operating-system controlled source but may be cleared or made unavailable by an administrator or attacker. Do not assume immutability.
2. **PowerShell collector** executes built-in Windows tooling. It operates under the scheduled user's permissions; access-denied must be treated as reduced visibility.
3. **SQLite** contains event-derived metadata and delivery state; it is not tamper-proof. Back it up and set proper file permissions.
4. **Windows Credential Manager** holds the user's Gmail App Password; compromised user sessions can still abuse credentials.
5. **Gmail SMTP** and external email delivery are separate trust and availability domains.

## Threats and mitigations

| Threat | Existing control | Residual risk |
|---|---|---|
| More matching events than scan cap | Cursor-aware oldest-first query | Backlog could grow without bound; no published stress limit |
| Email outage | Pending outbox, retry on later scans | Repeated failures; persistent retry cooldowns |
| Disabled event channel | Reports last successful read and latest error | Limited coverage; does not repair permissions |
| Spoofed / noisy signals | Rule filtering and 4625 burst threshold | False positives; no username/IP grouping |
| Stolen email credentials | Windows Credential Manager, no plaintext files | Theft possible with compromised account |
| Process termination | Task Scheduler restarts at logon/restart settings | Not tamper-resistant; no service watchdog proof |
| Concurrent scans | Per-event cursor persisted | No explicit cross-process single-instance mutex; avoid launching extra watchers |
| Confidential alert data leakage | Limited email fields | Email still leaves the machine |

## November 2026 installation finding

A real installation used a highest-privilege task pointing to an executable writable by the same user's ordinary processes. The candidate updater creates a new administrator-owned directory beneath Program Files, grants users read and execute access, verifies copies and registers a limited interactive task. It retains previous images and never launches an installed binary from its administrative session. Verify the resulting ACLs, task state and channel visibility on Windows.

The logged-in user can still change the local SQLite database, notification configuration and delivery state. A compromised session could redirect alerts, stop monitoring or abuse accessible credentials. A privileged administrator can change the installation. The operator still needs to trust the build inputs and dependencies. Hash comparison in the updater detects copy errors and provides no publisher authentication.

## Assumptions

Supported Windows Event Log APIs, PowerShell, permissions to read selected channels, and network access to Gmail on TCP 465. Python/PyInstaller binaries built for the Windows architecture. Only the local machine is in scope.

## Out of scope

Active defense, malware removal, reverse shell detection, process injection detection, enterprise SIEM integration, centralized telemetry, signed installers, hardened update channel, and end-user remote management.
