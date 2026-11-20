---
title: "SentinelForge"
subtitle: "Complete Project Documentation | Architecture, Implementation, Validation, Use Cases, Limitations & Future"
author: "Tanya Jain | BSc Cybersecurity, First Year | RIT Dubai"
date: "Project closeout snapshot — 20 November 2026"
lang: en-US
---

> **PROJECT STATUS — COMPLETED RESEARCH PROTOTYPE / PORTFOLIO RELEASE CANDIDATE**  
> Core functionality has been demonstrated on the developer's Windows 11 laptop. This document describes the observed implementation, measured evidence and limitations. It does **not** claim production certification, guaranteed attack detection or independent enterprise deployment.  
> **Evidence-anchored commit:** `566d26eab73aaa3ed6cf9b01763c32dd112e5c78` (`capstone/windows-validation`). Stable release candidate: `feature/detection-v2`; contextual v3 remains experimental.  
> **Repository:** https://github.com/tanyajainn/SentinelForge

## Guide map

| Understanding the project | Engineering and operation | Evidence and next steps |
|---|---|---|
| Executive overview; sections 1–3 | Sections 4–9: backend, frontend, detections, individual/campus/industry and privacy | Sections 10–12: validated results, unfinished gaps and optional future roadmap |
| Use it and explain it | What runs, where data is stored, what the screens show | Sections 13–17: portfolio pitch, safe commands, repo map, closeout, glossary and sources |

# Executive overview

**In one sentence:** SentinelForge is a lightweight, Python-based Windows endpoint security monitoring prototype that reads selected Windows Event Logs, detects predefined suspicious patterns, stores traceable alerts in SQLite, and notifies an operator through Gmail while providing local dashboards and optional privacy-limited campus reporting.

**Why it exists.** Windows records important security activity, but an ordinary user may not inspect the Event Viewer regularly or understand which records matter. SentinelForge turns selected records into reviewable security findings with event references, time, priority and suggested investigation steps. It is designed to be explainable and relatively privacy-conscious, not to silently block everything suspicious.

**What it is not.** It is not an antivirus, malware scanner, kernel sensor, complete endpoint detection and response platform (EDR), security information and event management system (SIEM), managed security service, or proof that every threat is detected. Alerts are signals requiring investigation, not confirmed incidents.

**Current disposition.** As a first-year undergraduate research/portfolio prototype, the project is suitable to freeze, document and demonstrate. Fresh-machine installation, independent real-world detection accuracy and repeated reboot/outage tests are still future validation rather than prerequisites for calling this version complete.

# 1. The problem, audience and value

A Windows PC generates many low-level event records. Individually they can be hard to interpret; a sequence may be more meaningful than one record. For example, five failed logons in ten minutes could merit a review, but could also result from a legitimate user entering an outdated password. Likewise, a new service or Windows account may be authorized or unexpected. SentinelForge attempts to make these patterns visible while maintaining the distinction between **recorded event**, **detection rule**, **alert** and **confirmed compromise**.

Who can use the current prototype?

- **Personal laptop owner / student:** monitor a single Windows machine, inspect alerts, confirm changes, learn event-driven security monitoring and receive email notifications.
- **Instructor / laboratory:** demonstrate detection pipelines, Windows auditing, stateful processing, alert evidence, test automation and false-positive limitations.
- **Campus IT pilot:** publish alias-labelled summaries from authorized test endpoints to an IT-controlled SMB share and inspect a combined, offline HTML view. This is an optional pilot workflow, not turnkey central security management.
- **Industrial security team:** use the design as a learning or research reference only. Enterprise deployment would require a much larger set of security, scale, operations and governance controls.

# 2. What happens from a Windows event to an email?

```text
WINDOWS ENDPOINT
  Windows Event Logs: Security | System | Defender Operational
        |
        v
  PowerShell Get-WinEvent collector (XPath + RecordID cursor)
        |
        v
  Python event normalization and detection/correlation rules
        |
        v
  SQLite transaction
    - alert records & evidence
    - per-channel cursor/health
    - correlation history
    - notification queue & delivery status
       |                              |
       v                              v
  Local dashboard / reports      Gmail SMTP/TLS notifier
  (browser + HTML)               (Windows Credential Manager)
       |                              |
       v                              v
  User / investigator            Recipient inbox

OPTIONAL CAMPUS PILOT (separate workflow):
  Endpoint SQLite -> privacy-limited publisher -> IT-controlled SMB share
      -> IT-side roster/read-only HTML dashboard (15-second refresh)
```

### Worked example: repeated failed Windows sign-ins

1. Windows records failed authentication events (Security Event ID **4625**), provided auditing is enabled and the account can read the channel.
2. Approximately every **10 seconds**, the installed background agent polls for selected new records, in capped batches of up to 500 per channel per scan. Its reader uses an `EventRecordID > last_processed` condition *inside* the Windows XPath query and requests the **oldest** matches first.
3. Python extracts event metadata (channel, RecordID, Event ID, UTC time, provider, selected identity/source fields) and passes it into rule evaluation.
4. A configurable burst rule (default **5 failures in 10 minutes**) may generate an alert. Where a trustworthy public IPv4 address is present, the rule groups by source; if absent, a less-specific legacy path may be used. A later successful sign-in may provide advisory correlation only if sufficient matching evidence exists.
5. SQLite writes any alerts, correlation history and updated cursor transactionally so a later scan can continue without intentionally replaying the same records.
6. An eligible new alert enters the notification flow; an email may be submitted via Gmail SMTP. The recipient still needs to verify inbox delivery when measuring delivery success.
7. The user can read the alert in the local dashboard, export evidence or investigate the linked Windows Event Log record. **The alert does not establish a break-in.**

# 3. Technology stack and system components

| Layer | Actual technology | Purpose |
|---|---|---|
| Core/backend | Python 3, standard library | Rules, event objects, state, reports, CLI, process control |
| Operating-system collector | PowerShell / `Get-WinEvent` / Windows Event Log XPath | Retrieve selected Security, System and Defender records |
| Persistent storage | SQLite database | Alerts, cursors, status, deduplication, correlation and notification state |
| Background runtime | Windows Task Scheduler | Starts user-scoped monitor at logon; monitoring proceeds without open terminal |
| Email transport | Gmail SMTP over TLS and Python `smtplib` | Outbound alert messages to a configured recipient |
| Credential storage | Windows Credential Manager via `keyring` | Avoid storing Gmail App Password directly in source or plaintext config |
| Local frontend | HTML/CSS rendered by Python, local HTTP server | Browser dashboard on `127.0.0.1:8765`, recent alerts and counts |
| Reporting frontend | Generated HTML and CSV | Printable pilot summaries and investigation exports |
| Campus preview | Python publisher, private SMB share, static HTML | Multi-endpoint read-only summary without publishing raw local logs |
| Windows distribution | PyInstaller binaries, PowerShell scripts, ZIP | Portable command line and separate background executable |
| Tests & automation | Python `unittest`, GitHub Actions | Regression checks on Windows and Linux; release workflow exists |

**Backend versus frontend, simply:** The backend is the engine that *does the monitoring, analysis, storage and sending*. The frontend is the interface a human *looks at* (the local dashboard and generated reports). SQLite is the durable memory between them. The frontend does not itself detect attacks; the backend works even if no browser is open.

# 4. Backend in detail

## 4.1 Event collector (`sentinelforge/windows.py`)

The collection layer requests only configured event IDs. It runs a PowerShell command that queries Windows through its built-in event infrastructure rather than inventing an untrusted event source. It uses a per-channel cursor to avoid re-reading already processed records and requests older matching records before newer ones when batches are capped. It normalizes relevant fields into a Python `Event` data structure.

**Important condition:** Some event IDs are absent until their audit policies are enabled. Channel access varies with Windows privileges and edition. Read errors must be considered loss of visibility, not absence of threats. The implementation tracks the last successful read and errors for each channel.

## 4.2 Rule engine (`sentinelforge/core.py`)

The core contains a table of known event IDs with rules and severity, a stateful `Detector` and an SQLite `Store`. There are **direct event rules** (such as Security log cleared) and **multi-event correlations** (such as repeated failures or failures followed by a matching success). Priority labels reflect investigation urgency, not mathematical probability that an attacker is present.

The source-aware failed-logon detector depends on source information quality. Private/reserved addresses and unidentified sources are not treated as verified public-IP identities. This is conservative, but it necessarily misses some plausible attack patterns and generates alerts on benign repeated mistakes.

## 4.3 Persistent database (`%USERPROFILE%\SentinelForgeData\events.sqlite3`)

Key schema concepts include:

- `alerts`: saved detection records with ID, time, rule, severity and JSON payload/evidence.
- `cursor`: last processed EventRecordID by channel.
- `channel_health`: last check, last successful read and collection error.
- `detector_state` / `source_failure_state`: persisted failed-login windows across processing cycles.
- `correlation_evidence` / `correlation_emissions`: bounded evidence and duplicate emission control for selected multi-event rules.
- `notification_meta`: historic-notification baseline; older alerts are stored but excluded from new email delivery.
- `notification_state` / `delivery`: email outcome and attempt information.
- `emailed_config_changes`: suppression/grouping state for repeated Defender configuration emails.

**Consistency design:** Ingestion commits alert records, correlation state and cursor movement within the same database transaction. This reduces mismatch after interruption. It does not make SQLite tamper-proof or prove perfect processing under every crash/OS failure.

## 4.4 Agent lifecycle (`sentinelforge/__main__.py`)

The installed agent loops, performs `scan(...)`, attempts eligible notifications and sleeps about **10 seconds**. Task Scheduler launches it under the configured Windows user at sign-in. The configured task has a logon trigger, limited run level on the hardened candidate and restart-related settings. Its observed `267009` result corresponds to the normal 'currently running' scheduler state, not a crash.

Closing PowerShell or VS Code does **not** stop the installed background task. Closing the browser does not stop collection. Stopping or uninstalling the task is a separate administrative/user action; it is unnecessary for declaring development complete.

## 4.5 Email delivery and reliability (`sentinelforge/channels.py`)

The app formats an email with a useful priority, event title, time, local event reference and human review action. It sends through Gmail SMTP using configured credentials obtained from Windows Credential Manager. The app intentionally excludes most raw local evidence from routine email to reduce exposure. A notification state is saved for eligible alerts, and transient SMTP failure causes backoff and retries rather than intentional deletion of stored alerts.

The user performed a self-test through the **installed background agent**. The resulting alert **#790** was submitted successfully and the actual inbox arrival was separately confirmed. The self-test is a harmless **synthetic alert**, not evidence that a real malicious Windows logon was created or detected. The reported `email new undelivered: 0` describes the post-baseline queue; the legacy count of 790 includes historical alerts and must **not** be called 790 failed emails.

## 4.6 Response guidance and opt-in firewall controls

A threat-assessment component offers conservative next steps, and the `response.py` module includes an explicit-confirmation manual Windows Firewall workflow. The monitoring engine does **not** automatically block IPs or remediate infections. This design avoids turning a potentially false positive into an automatic network outage. Manual actions require review, documented reason and appropriate Windows permissions.

# 5. What the frontend looks like and does

## Personal dashboard

- A Python HTTP server serves local HTML/CSS at `http://127.0.0.1:8765`.
- The dashboard reads SQLite **read-only**; it does not make the detection decisions.
- It shows counts by severity, up to **100 recent alerts**, recent scan information and recorded email submission counts.
- The page refreshes periodically (the local dashboard HTML uses a **30-second** refresh).
- It binds only to loopback on the developer machine, rather than exposing a public web service.

## Reports and exported evidence

- **Pilot report:** `python -m sentinelforge pilot-report --from-date YYYY-MM-DD --to-date YYYY-MM-DD`. Produces a printable HTML summary of stored findings, notification states, collection health and recommended review actions.
- **CSV export:** `python -m sentinelforge export-csv`. Offers an investigation-oriented table that may contain sensitive event details; protect it accordingly.
- **Status/CLI:** `SentinelForge.exe status` reports task health, monitored channels, recent reads, notification state and database location.

## Campus live-view frontend (optional pilot)

A separate publisher copies a **limited alert summary**, not the entire raw log, to one authenticated per-endpoint folder on an IT-controlled SMB share. An IT operator supplies a device roster to render a standalone HTML page listing reporting/overdue/missing endpoints and up to 100 recent alerts. It refreshes every 15 seconds and supports an offline/reporting model. It is **not** a hosted website, managed SaaS, remote control console or production SOC.

# 6. Detection catalogue: what can trigger an alert?

| Windows source | Event IDs | What SentinelForge can flag | Interpretation caveat |
|---|---|---|---|
| Security | 4625 | Failed-logon bursts and conditional correlations | Common benign mistyping/service-password cases |
| Security | 4624 | Used to correlate matching successful logon after failures | Does not usually alert alone |
| Security | 4720, 4722, 4726 | User account created, enabled, deleted | Often legitimate administration |
| Security | 4728, 4732 | Member added to security-enabled group | Requires authorization context |
| Security | 4697, 4698 | Service installed / scheduled task created | Authorized software may generate these |
| Security | 1102 | Security audit log cleared | High-signal, not automatic attribution |
| Security | 4719 | Audit-policy changes | Must examine exact policy and actor |
| Security | 4740 | Account lockout | Could be user errors or attack |
| System | 7045 | Windows service installed | Check software ownership |
| Microsoft Defender | 1116, 1117, 1118 | Malware detection, remediation, remediation failure | Defender remains the detecting/remediating engine |
| Microsoft Defender | 5001, 5007, 5013 | Real-time protection disabled, configuration change, protected change blocked | Some config changes are routine and benign |

**Rule details:** The default burst threshold is five failures within ten minutes. Selected source-aware rules can attach recurrence information and advisory failure-to-success evidence. Identical Defender configuration-change emails (ID 5007) can be grouped for a 60-minute processing window while the local alerts remain stored. Not all event IDs are always generated, even on a correctly configured Windows machine.

# 7. A day in the life: how a person uses SentinelForge

**First setup (new machine, not a step the current user needs to repeat):** Obtain a trustworthy Windows release, extract both executables, run ordinary-user setup, supply an email recipient and a Gmail sender with an App Password, confirm that the task exists and that required channels can be read. The hardened installed binaries are placed under a protected Program Files directory using the documented updater. A portable ZIP does not magically create a global Windows command on a fresh system.

**Normal day:** The login-triggered background task starts when the configured Windows user signs in; the user need not keep PowerShell open. The agent reads events, records alerts and retries eligible notification attempts. The owner occasionally checks the email inbox, local dashboard or `status` CLI. When an alert appears, they inspect the source event in Event Viewer, compare the time with known maintenance/user actions, and only then decide whether to escalate.

**Example human judgment:** An unexpected account creation alert is high priority for review, but the correct first step is checking whether the account was created by an administrator for an approved reason. The tool does not know authorization policy by itself.

**If Gmail is offline:** New eligible alerts stay in persistent local state and SMTP attempts back off. The tool is not an availability guarantee: an operator must inspect health and evidence after an outage.

# 8. Personal, laboratory, campus and industrial differences

| Dimension | Personal single laptop | Authorized campus pilot | Industrial / enterprise standard |
|---|---|---|---|
| Typical deployment | One user's Windows endpoint | Limited named/alias-labelled pilot endpoints | Hundreds/thousands of managed endpoints |
| Collector | Local Windows event rules | Similar endpoint-level rules | Managed telemetry across endpoints, network, identity, cloud |
| Storage | Local SQLite | Local SQLite plus limited summary batches on SMB | Central resilient storage, retention and access controls |
| Dashboard | Local browser on loopback | Offline IT roster/HTML report | Multi-tenant SOC dashboards, search, case management |
| Identity & control | Windows user context | Per-device account and IT-managed share permissions | Role-based access, SSO, MFA, audit trail, central policy |
| Notifications | Gmail to an individual | Endpoint or local-only pilot workflows | Enterprise routing, on-call rotations, ticket/incident integration |
| Security hardening | Local protected binaries and secrets | IT authorization and share ACLs required | Signed installers, MDM/EDR integration, policy enforcement, tamper resistance |
| Detection confidence | Explainable rule triggers | Pilot review and manual ground truth | Mature detections validated on varied real operational datasets |
| Reliability | Observable single-device health | Missing and overdue publisher status | HA, failover, fleet health SLAs, resilient queues, monitoring |
| Current SentinelForge readiness | **Demonstrated on developer laptop** | **Prototype workflow, limited field validation** | **Not ready for production deployment** |

**What “different per person” really means:** Two personal users may have different Windows editions, privileges, auditing settings, backgrounds, installed applications and legitimate login behaviors. Those differences affect which events exist, which rules trigger and how much noise appears. The algorithm does **not** automatically learn a personalized normal baseline in the way a mature anomaly-detection service might. To adapt it safely, one would tune rules with documented expected workflows and review labels. Campus usage also introduces consent, data minimization, endpoint ownership and governance requirements.

# 9. Security, privacy and design choices

- **Data locality:** Full event-derived alert evidence is normally stored in the user's own SQLite file, not uploaded to a central cloud by default.
- **Credential handling:** Gmail App Password is retrieved via the Windows credential store (`keyring`); it is not intentionally checked into Git or saved alongside the local config as plain text.
- **Least privilege:** The hardened release uses an interactive, limited scheduled task and protected executable directory. Do not confuse this with tamper-proof security.
- **Limited email detail:** Most raw evidence remains local; email carries investigation information and necessarily leaves the endpoint through Gmail.
- **No silent blocking:** A benign alert should not automatically disconnect someone or modify firewall policy.
- **Read-only reporting:** The local dashboard and faculty report open SQLite for read-oriented display/reporting.
- **Boundaries:** A compromised Windows user, administrator, or endpoint can tamper with the monitor, logs, configs and credentials. Cleared/rotated event logs can remove evidence. Incorrect Windows auditing can make the system blind.
- **Campus governance:** Obtain institutional permission, named pilot participants, per-endpoint share permissions and retention policies before transferring even summary metadata.

Do not publish `events.sqlite3`, `notifications.json`, `monitor.log`, credential data, unredacted alert evidence or screenshots containing personal email addresses, IPs, usernames or device identifiers. Share sanitized results and source code, not the live database.

# 10. Testing and results — exactly what has been verified

## 10.1 Evidence at the closeout commit

| Evidence item | Observed result | What it demonstrates / does not demonstrate |
|---|---|---|
| Source revision | `566d26eab73aaa3ed6cf9b01763c32dd112e5c78` | Exact code state used for Windows validation branch |
| Regression tests | **105/105 passed**, as reported after SQLite cleanup fix | Software behavior tests; **not** empirical attack accuracy |
| GitHub Actions | Windows and Linux CI successful for this revision | Cross-platform regression execution; not Windows fresh install |
| Live reference audit | **30/30 matched** sampled alerts to Event Log references; zero missing/mismatch/query errors | The sampled alerts point to actual present Windows records; not complete event coverage or attack confirmation |
| Installed agent | Scheduler task `Running`, logon trigger enabled | Running status and configured automatic start; not 3 successful reboot trials |
| Three Windows channels | Security, System, Defender all showed successful reads on Nov 20, 2026 | Operational access on the current Windows installation |
| Stored alerts | **790** at time of status capture | Local history size; not 790 active threats |
| Email queue | **0 new undelivered** post-baseline | No currently pending new email state at observation time; legacy count includes historical alerts |
| End-to-end self-test | **#790 submitted by installed agent and independently confirmed in inbox** | Real delivery for one synthetic test; not statistically measured delivery SLA |
| ZIP integrity | SHA-256 check **PASS** against documented 2026-11-20 ZIP | Local build artifact matches recorded checksum; not publisher signing |
| Windows restart recovery | **Not measured as a reboot test** | Last OS boot was Nov 6; task was launched Nov 19; this does not establish reboot recovery |

The CI run for the reported commit is: https://github.com/tanyajainn/SentinelForge/actions/runs/44787955383. The source candidate documentation mentions **108 tests** in a separate development context with opt-in v3 research tests; that figure must not be substituted for the **105/105 explicitly reported on the validated closeout branch**.

## 10.2 Synthetic 10,000-event benchmark — two recorded executions

| Run | Events | Batch size | Elapsed | Calculated rate | Alerts | Consistency checks |
|---|---:|---:|---:|---:|---:|---|
| Saved uploaded JSON | 10,000 | 500 | **0.1729 s** | **57,851.82 events/s** | 34 | All four passed |
| Later terminal output | 10,000 | 500 | **2.3294 s** | **4,292.89 events/s** | 34 | All four passed |

Both are **synthetic internal processing** measurements. They differ substantially; do **not** claim a stable production throughput or extrapolate to `Get-WinEvent` collection, actual live Windows event generation, email, storage growth or CPU cost. The four checks report that cursor preservation, alert preservation, duplicate-replay prevention and SQLite integrity succeeded for their respective benchmark runs. The uploaded JSON is retained in the evidence bundle and includes `dataset: synthetic`.

## 10.3 Synthetic detection effectiveness and failure cases

A reproduced seeded failed-logon evaluation contains **576 synthetic episodes** (TP=288, FP=171, FN=0, TN=117), giving precision **62.7%**, recall **100%** and F1 **0.771** for that particular constructed scenario mix. This is **not** an estimate of real-user precision or all-threat detection coverage.

A **deliberately adversarial synthetic audit** gives the deployed source-IP v2 policy TP=0, FP=960, FN=720, TN=240 (F1=0.000) on its eight constructed counterexample families. That challenge reverses assumptions of the easy fixtures: slow spraying can slip below thresholds, while fast legitimate errors can trigger alarms. This failure is a useful documented research limitation, not evidence that the Windows monitoring process failed to run. The separate experimental contextual policy belongs to research, **not** the deployed v2 release.

**Defensible conclusion:** The project has credible evidence of implemented Windows monitoring, persistence and notification delivery on the developer's installation. Independent real-world detection validity and reliable deployment across machines remain open research/engineering questions. The sample of 30 matched alert references cannot yield a missed-event rate because it starts from alerts already present in the database.

# 11. What remains unfinished — documented, not required tonight

| Gap | Why it matters | Suggested future evidence |
|---|---|---|
| Independent held-out labelled data | Synthetic labels omit real authorization context | Consent-based anonymized traces; independent reviewers; TP/FP/FN/TN |
| Windows clean install | Developer machine may contain setup/history assumptions | Disposable Windows VM with ordinary-user setup and task ACL review |
| Controlled recovery | An operational running task is not proof of automatic resume after crashes/reboots | 3 restart trials, an SMTP outage, missed-event reconciliation |
| Full live throughput / resource use | Synthetic functions exclude Windows collector and SMTP | CPU/RAM/storage and end-to-end median/p95 latency over long sessions |
| Signing / secure updates | ZIP hash checks integrity, not trusted publisher authenticity | Signed binaries, checked update process, rollback |
| Enterprise controls | Local user-space agent lacks fleet control and strong tamper resistance | SSO/RBAC, remote policies, fleet telemetry/health, HA |
| Mac feature parity | Preview only checks launch plist configuration | Mac-specific security telemetry and native acceptance tests |
| Risk of false positives | Benign admin actions and repeated passwords can be noisy | Rule tuning on authorized real/held-out workflows |

**Scope decision:** These are future work. The project can be described as **complete as a first-year research prototype** without claiming those gates were passed. New features should be planned only if there is a clear use case or independent research objective.

# 12. Future roadmap (optional, not a new task list)

**Near-term research:** collect ethical, permissioned and independently labelled benign/attack episodes; evaluate true/false positives and negatives; distinguish source uncertainty; compare the frozen v2 policy with any context-aware candidate on the same held-out set.

**Operational hardening:** verify installation on a clean Windows VM; quantify restart/outage behavior, latency and sustained resource use; digitally sign build artifacts and document update recovery. Preserve safe-by-default manual response decisions.

**Campus evolution:** formal IT consent and governance, centralized summary ingestion with real authentication, per-device identities, RBAC, retention policy, fleet health and searchable history. Make reporting robust before considering remote response.

**Long-range product research:** integrations with existing EDR/SIEM/ticketing platforms, structured analyst feedback, multi-OS sensors and more robust correlation. These are **proposals**, not currently delivered functionality.

# 13. Honest portfolio presentation and demo script

### Resume / project description

**SentinelForge — Windows Endpoint Security Monitoring Research Prototype**  
Developed a Python-based Windows event monitoring and alerting system with RecordID-aware PowerShell collection, rule-based correlations, transactional SQLite persistence, Windows Task Scheduler automation and Gmail SMTP alerts. Built local and campus-pilot HTML reporting, regression tests and reproducible synthetic evaluations. Validated 30 sampled stored alert references against source Windows Event Logs and confirmed installed-agent inbox delivery, while explicitly documenting false-positive and independent-deployment limitations.

### 60-second presentation

“SentinelForge is a lightweight Windows security monitoring prototype I developed to make native security events easier to understand and act on. Its backend uses PowerShell to read selected Windows Event Logs, then a Python rule engine checks for patterns such as repeated failed sign-ins, account changes, service installations and Defender protection events. Findings, event references and delivery state are stored in SQLite. A background Windows task continues monitoring while a local browser dashboard and optional Gmail alerts show the results. I also built a privacy-limited campus pilot view. On my own Windows laptop, I verified that the installed agent runs, all three configured channels are readable, 30 sampled alerts point to real Event Log records, and a self-test message arrived in my inbox. It is intentionally advisory-only, and I am careful not to claim synthetic detection scores predict real-world accuracy.”

### Three-minute demonstration order

1. Show the GitHub repository and the exact validated commit (`566d26e`).
2. Show the installed Scheduled Task as **Running** and the limited logon trigger.
3. Run **status** using the CLI next to the task action; explain Security/System/Defender freshness.
4. Open the local dashboard; interpret an event reference and priority without claiming an intrusion.
5. Show the redacted evidence audit JSON (30/30 matched) and test/CI result.
6. Show the inbox-confirmed synthetic self-test #790, clearly labelled test-only.
7. Close with the adversarial false-positive/false-negative finding and the future validation boundary.

### Questions a reviewer might ask

**Q: Is it antivirus?** No. It monitors selected event patterns; Microsoft Defender still performs its own malware detection and remediation.

**Q: What is the backend?** Python rule engine, PowerShell Windows Event Log collection, SQLite state and SMTP notification logic, executed by a Windows background task.

**Q: What is the frontend?** Local Python-served HTML/CSS dashboard, generated printable HTML/CSV reports and an optional campus-pilot HTML dashboard.

**Q: Is there machine learning?** Not in the deployed rule-based Windows v2 detection path. Experimental contextual scoring does not change that claim.

**Q: Does it detect hackers?** It flags configured suspicious *signals*. Some attacks are missed and some legitimate activity triggers alerts; an investigator decides whether they represent compromise.

**Q: How does it avoid duplicates?** Per-channel RecordID cursors, transactional persistence and notification-state controls, with separate grouping for some repeated Defender 5007 emails. It does not promise globally exactly-once mail delivery.

**Q: What if the device is offline?** It records locally and retains eligible email state for retries, subject to the remaining limitations of the OS, user account, local disk and Gmail availability.

**Q: Does the dashboard collect data?** No. The local dashboard displays a read-only view of backend data already in SQLite.

**Q: Are the two SentinelForgeAgent processes a bug?** Not necessarily. A PyInstaller one-file executable can show a parent bootloader and child process; the observed parent-child chain is consistent with that.

**Q: Why not deploy it industrially today?** It has not proven multi-host secure administration, independent detection accuracy, high availability, signature/update security, privacy governance or tamper resistance required by enterprises.

**Q: Does “30/30 matched” mean 100% detection?** No. It means those *already-generated alerts* correspond to existing Windows records. It provides no count of missed attacks or unalerted events.

**Q: Why do the two speed measurements differ?** They are separate synthetic runs with different observed elapsed times; there is not enough controlled benchmarking to infer a steady throughput SLA.

# 14. Operator command reference — safe and explicit

The following use the already-installed protected CLI, rather than assuming `SentinelForge` on PATH points to the current build:

```powershell
$task = Get-ScheduledTask -TaskName 'SentinelForge Security Monitor'
$agent = $task.Actions[0].Execute
$cli = Join-Path (Split-Path $agent) 'SentinelForge.exe'
& $cli status
```

**Optional CLI actions** (not necessary for closeout):

```powershell
& $cli self-test     # Inserts a new synthetic alert and attempts an email
& $cli scan          # Collect selected events once
& $cli dashboard     # Opens/hosts the local dashboard; close that terminal to stop only dashboard server
& $cli export-csv    # Exports investigation evidence; handle as sensitive
```

**Developer commands** (from the source checkout, run only if genuinely needed in future):

```powershell
python -m unittest discover -s tests -q
python -m evaluation.live_evidence_audit --sample-size 30
python -m evaluation.performance_benchmark --events 10000 --batch-size 500
```

Do **not** invoke `stop`, `uninstall`, `setup`, the privileged updater, firewall apply/rollback or a new benchmark merely to mark the project as finished. A final document commit is sufficient. Keeping the background task running is separate from continuing development.

# 15. Repository map for a new maintainer

| Location | What to read it for |
|---|---|
| `README.md` | Main project explanation, features, commands and prototype boundaries |
| `sentinelforge/__main__.py` | Command-line interface, installed agent loop, setup, self-test and notification dispatch |
| `sentinelforge/windows.py` | Windows Event Log collection and field normalization |
| `sentinelforge/core.py` | Event/Alert classes, rules, SQLite schema, persistence and correlations |
| `sentinelforge/channels.py` | Email content, suggested action and SMTP send support |
| `dashboard.py` | Local read-only HTML dashboard and HTTP handler |
| `sentinelforge/pilot.py` / `reporting.py` | Printable faculty report and evidence exports |
| `sentinelforge/campus.py` / `campus_dashboard.py` | Optional SMB publisher and multi-device read-only HTML view |
| `sentinelforge/macos.py` | Limited macOS launch configuration monitoring preview |
| `sentinelforge/response.py` | Separately invoked manual/dry-run firewall controls |
| `evaluation/` | Replay scripts, synthetic benchmarks, independent-holdout harness and audit tools |
| `docs/CAPSTONE_EVIDENCE.md` | Proposed future capstone evidence gates; do not treat as completed results |
| `docs/THREAT_MODEL.md` | Boundaries, mitigations and residual risks |
| `docs/RELEASE_CANDIDATE.md` | Stable v2 Windows candidate, archive SHA-256 and known limits |
| `.github/workflows/` | Regression and build/benchmark workflows |

# 16. Closeout record and reproducibility

**Frozen evidence revision:** `566d26eab73aaa3ed6cf9b01763c32dd112e5c78` — exact source commit in the uploaded `commit.txt` and GitHub `capstone/windows-validation` branch. A later documentation-only commit will not retroactively change the tests attached to this source revision.

**Uploaded local artifacts reviewed for this guide:** `commit.txt`; `live_evidence_audit.json` generated 2026-11-20 at 18:03 UTC with 30/30 matches; `performance_10k.json` containing the earlier 0.1729-second synthetic run. **Not separately uploaded in this conversation:** the full local `capstone-validation.txt` transcript or the local copy of `CAPSTONE_EVIDENCE.md`; the repository version of `docs/CAPSTONE_EVIDENCE.md` was read directly from the validated branch.

**Stable Windows candidate ZIP fingerprint (only for the original 2026-11-20 archive):**

`4BE58DB366B7F132A25DC8B18561D9BF5DEDCF626608D5CDB5BF6DC5292A34DE`

**Archival recommendation:** Retain the original evidence files, the completed guide, the exact source commit, a release ZIP checksum and the CI URL. Record exact test conditions rather than presenting proposed research gates as completed achievements. If a new feature branch is started later, treat it as **vNext**, not a reason to retroactively keep v1 development open.

**Final status statement:** **SentinelForge v1 — development complete as an individual first-year cybersecurity research/portfolio prototype; operational on the developer's Windows machine; independently validated production deployment and real-world threat-detection accuracy not claimed.**

# 17. Short glossary

| Term | Plain-language meaning |
|---|---|
| Event ID | Windows' numeric category for a recorded event |
| RecordID | The event's ordered reference within a Windows log channel |
| Cursor | Stored last processed RecordID, so collection can resume |
| Detection rule | A transparent condition that may generate an alert |
| Correlation | Connecting multiple recorded events into a more meaningful signal |
| Alert | A stored finding generated by a rule, not proof of malicious intent |
| Severity | Review priority; not a calibrated chance of compromise |
| SQLite | Local embedded database storing state and evidence |
| SMTP | Email submission protocol; acceptance is not guaranteed inbox receipt |
| CI | Automated tests executed by GitHub on changes to source |
| EDR | Enterprise endpoint detection/response; broader than this prototype |
| SIEM | Enterprise centralization/search/correlation of security events |
| False positive | Benign activity incorrectly flagged as suspicious in a labelled benchmark |
| False negative | Labelled suspicious episode that the rule fails to flag |
| Held-out evaluation | Testing against labelled cases not used to tune the detector |
| Release candidate | Functional build intended for verification, not certified production readiness |

# References / source notes

This guide combines inspected repository content at commit `566d26e` with user-supplied local validation artifacts and console observations. Source code paths above are the traceable documentation of implementation. Main supporting repository files:


**Implementation sources:** [Project README](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/README.md) · [Core detector and store](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/sentinelforge/core.py) · [Windows collector](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/sentinelforge/windows.py) · [Agent and CLI](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/sentinelforge/__main__.py) · [Dashboard](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/dashboard.py).

**Security and evidence sources:** [Threat model](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/docs/THREAT_MODEL.md) · [Evidence protocol](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/docs/CAPSTONE_EVIDENCE.md) · [Adversarial audit](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/docs/ADVERSARIAL_EVALUATION.md) · [Release candidate](https://github.com/tanyajainn/SentinelForge/blob/capstone/windows-validation/docs/RELEASE_CANDIDATE.md) · [CI run](https://github.com/tanyajainn/SentinelForge/actions/runs/44787955383).
