# Research plan: from prototype to graduate-level security research

## Research question
Can a local-first, explainable, low-cost detection pipeline identify selected Windows host attacks with acceptable false-positive rates and latency compared with baseline Windows Defender alerts?

## Hypotheses
- H1: Correlation across Windows Security, System, Defender and Sysmon telemetry increases recall for a fixed threat scenario suite.
- H2: Entity-aware burst detection reduces false positives compared with global failed-logon thresholds.
- H3: Local processing plus privacy-preserving notifications reduces sensitive data egress without materially reducing triage quality.

## Proposed methodology
1. Define explicit threat scenarios and ATT&CK technique mappings.
2. Establish a clean Windows VM baseline and collect benign telemetry.
3. Execute **authorized**, isolated, documented simulations (e.g., Atomic Red Team tests reviewed for safety).
4. Annotate ground-truth attack start/end, expected logs, and response labels.
5. Compare rule sets against Defender-only baseline.
6. Report precision, recall, F1, median/p95 alert latency, CPU/RAM, and missed telemetry.
7. Evaluate evasions, permissions, log tampering, and false positives; disclose limits.

## Ethics and reproducibility
Use isolated lab VMs, no real victim data, no external scans, no production malware. Publish sanitized synthetic datasets, test harness, environment versions, and negative results.

## Deliverables to reach thesis quality
Literature review, explicit threat model, data collection protocol, labeled datasets, reproducible experiment suite, baselines, statistical confidence intervals, limitations, and a peer-reviewable technical report.

**The current repository is an early prototype, not yet a master's thesis.**
