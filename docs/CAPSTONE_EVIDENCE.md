# SentinelForge | Fourth-Year Cybersecurity Capstone Evidence Protocol

**Status:** Engineering upgrade proposal; this page is **not** a report of completed independent validation.

## Research claim worth testing

Can an explainable, privacy-conscious Windows Event Log monitor retain evidence and deliver useful detections across restarts and outages, and can carefully tested contextual correlation improve the discrimination between authorized failures and attack behavior compared with the deployed v2 policy?

## Non-negotiable distinctions

1. **Unit tests** test program behavior, not empirical threat-detection accuracy.
2. **Synthetic fixtures** test carefully chosen cases, not representative enterprise traffic.
3. **SMTP accepted** is not equivalent to a message arriving in an inbox.
4. **Running scheduled task** is not equivalent to validated end-to-end log collection.
5. **An alert** is not proof of malicious intent.
6. **Current stable v2** is distinct from experimental contextual v3. Do not silently ship v3.
7. **Automatic blocking** stays disabled. Firewall/response code is manual or simulation-only.

## Capstone evaluation gates

| Gate | Evidence to archive | Minimum acceptance criterion (proposed, not achieved) |
|---|---|---|
| Reproducible build | Commit SHA, Windows runner log, ZIP checksum, artifact, executable smoke tests | A fresh CI job builds and checks the complete ZIP |
| Cross-platform regressions | Ubuntu and Windows CI run URLs | Both OS test jobs green for the release commit |
| Clean Windows install | Test machine snapshot, OS/build, audit policy, install transcript | Successful ordinary-user setup and correct Scheduled Task privilege |
| Actual event-to-alert | Safe test event's channel, RecordID and UTC time; SQLite alert ID | Known authorized event creates an expected linked alert |
| SMTP to inbox | Alert ID, SMTP state and recipient arrival time (redacted) | Confirm delivery in at least 10 controlled trials; report failures rather than hiding them |
| Recovery | Three controlled restart trials and one network outage/reconnect | No lost stored evidence or unaccounted duplicate alerts in controlled trial |
| Backlog coverage | Generated RecordIDs, ingested RecordIDs, cursors | No skipped matching RecordIDs in measured capped batches |
| Detection quality | Frozen independent labels and scenario counts, exact fixture hashes | Precision/recall/F1 reported on held-out authorized scenarios, including hard negatives |
| Performance | CPU, RAM, disk and latency traces on actual Windows | Median/p95 event-to-alert/inbox times and sustained resource usage measured |
| Security review | Windows task ACL check, secret scan, protected binary ACLs, threat model | No credentials in checked-in files or package; security limitations disclosed |

## Held-out detection evaluation

Use `python -m evaluation.independent_holdout --input <sanitized.jsonl> --origin independent_lab --output evidence/holdout.json` **only** on real, authorized, independently labelled traces. Do not score raw `.evtx` files directly: the harness requires translated JSON Event objects, sorted ascending by channel RecordID. Each JSONL line is one *episode*, with `episode_id`, `label` (`attack` or `benign`), `scenario`, and `events` (a nonempty ordered list of `sentinelforge.core.Event` fields). Current harness supports one event-log channel per episode and resets SQLite state between episodes; it is not a substitute for multi-day persistent replay.

Suggested scenario classes:

- Targeted rapid guessing; slow password spray; multi-source low-rate guessing.
- Fast benign shared-NAT failures; service with stale credentials; password-reset mistakes.
- Unknown/private source; missing source; legitimate source rotation.
- Authorized account creation / privileged change versus unauthorized equivalent, with reviewer access to authorization records.

Freeze evaluation labels **before** changing thresholds. Keep the stable v2 detector as baseline. Use an entirely separate tuning subset if changing detection logic, then evaluate both policies on the identical held-out cases. Report the confusion matrix, denominators, all false-positive and false-negative cases, source-quality exclusions, and scenario prevalence. Request at least two independent label reviewers when feasible and document disagreement. Do not claim the benchmark represents the true population without sampling justification.

### Demo only (NOT validation)

```
python -m evaluation.independent_holdout --input evaluation/fixtures/holdout_demo.jsonl --origin synthetic_demo --output evidence/holdout-demo.json
```

The demonstration includes intentionally difficult negative and positive fixtures. A sample score is only a wiring check.

## Field-testing log template

| Trial ID | Windows version | Git SHA | Audit configuration | Event RecordID | Expected | Observed alert ID | SMTP accepted UTC | Inbox UTC | Outcome |
|---|---|---|---|---:|---|---:|---|---|---|
| T001 | pending | pending | pending | pending | pending | pending | pending | pending | not run |

Separate true-positive detection, false-positive event labels and operational delivery. Document failures. Redact names, IPs, device IDs, emails and logs before public publication; keep raw evidence in an access-controlled location.

## Promoting to 9/10 quality

Targeting a 9/10 capstone requires a **completed** evidence package, not simply this checklist: measured failure recovery, independently labelled detector comparisons, a reproducible Windows release, realistic resource/latency measurements, an articulated research question, and a demo that a supervisor can reproduce. The exact score remains examiner-dependent. Do not say independent validation is complete until it has been performed.
