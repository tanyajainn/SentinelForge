# Research protocol — evaluation plan, not measured results

**Research question:** How reliably does a lightweight Windows Event Log monitoring agent generate and deliver alerts for predefined suspicious events on a Windows 11 endpoint under changing event volume and connectivity?

## Hypotheses

- H1: Oldest-first, RecordID-filtered collection reduces skipped matching events compared with newest-first capped queries.
- H2: Persistent delivery state maintains at-least-once attempt semantics across temporary SMTP failures.
- H3: Detection recall is high for listed high-signal Windows event IDs under the stated permissions, but the 4625 burst rule produces both false positives and false negatives depending on local behavior.

## Experimental design

1. **Functional event capture** — Generate only benign, authorized test events for each supported ID in an isolated Windows VM; document which ones actually appear in each Windows edition.
2. **Backlog stress** — Replay or create test event bursts of 100, 500, 1,000, 5,000; compare event RecordIDs seen in the Windows Event Viewer versus SQLite alert/cursor progression. Avoid fabricating production event volume measurements.
3. **Alert correctness** — Use a labelled test corpus with known expected alerts. Measure TP, FP, FN, precision = TP/(TP+FP), recall = TP/(TP+FN), and F1. For burst behavior, include time windows at +/- 1s around the threshold, reboot between sequences, and cross-user events.
4. **Delivery latency** — Record the event's UTC timestamp, SQLite insert time, agent notification acknowledgement time, and actual recipient inbox arrival time. Summarize median, p95, and max by conditions; do not treat SMTP acceptance as inbox confirmation.
5. **Failure injection** — Disable network connectivity, revoke a test Gmail App Password, stop/restart the task, deny a channel, and remove/restore connectivity. Check retry behavior, duplication, and data preservation without touching the production database.
6. **Resource utilization** — Sample CPU, resident memory, disk growth, and process start count over 1/8/24 hours. PyInstaller one-file mode may legitimately show a bootloader parent + child process.
7. **Security audit** — Review executable/source for embedded credentials, SMTP configuration, permissions, task privileges, and unintended data transmission. Scan release binaries and sign releases when feasible.

## Required controls

Two independent Windows test systems or VMs; a dedicated disposable Gmail sender; consistent system clock/time zone; separate test database; fresh install; controlled network conditions. Document OS version, privilege level, event audit policy, all version hashes, command lines and raw logs.

## Reporting format

| Metric | Definition | Result |
|---|---|---|
| Event capture recall | matched RecordIDs ingested / expected matching RecordIDs | **Not measured** |
| Precision | TP / (TP+FP) | **Not measured** |
| F1 | 2PR/(P+R) | **Not measured** |
| Event-to-SMTP p95 | p95(notification ack time − event time) | **Not measured** |
| Inbox success rate | delivered test messages / attempted tests | **Not measured for this release** |
| Startup recovery | successful post-login startups / trials | **Not measured for this release** |

Passing unit tests supports software consistency but does not establish a detection performance claim. A master's-level research submission requires executed measurements, external validity discussion, and limitations, not just an attractive GitHub README.
