# SentinelForge — adversarial synthetic stress test

**Not production accuracy.** All event traces and labels are constructed hypotheses.
This dataset is deliberately difficult and must not replace the original benchmark.

Settings: 30 seeds, 8 episodes/case/seed, 10-minute window, threshold 5.

| Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |
|---|---:|---:|---:|---:|---:|---:|---:|
| legacy_channel | 240 | 1200 | 480 | 0 | 0.167 ± 0.000 | 0.333 ± 0.000 | 0.222 ± 0.000 |
| current_source_ip | 0 | 960 | 720 | 240 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 |
| experimental_contextual | 240 | 1200 | 480 | 0 | 0.167 ± 0.000 | 0.333 ± 0.000 | 0.222 ± 0.000 |

## Error breakdown

| Policy | Scenario | True label | Flagged | FP | FN |
|---|---|---|---:|---:|---:|
| legacy_channel | slow_password_spray | attack | 0/240 | 0 | 240 |
| legacy_channel | low_rate_distributed | attack | 0/240 | 0 | 240 |
| legacy_channel | private_ip_targeted | attack | 240/240 | 0 | 0 |
| legacy_channel | fast_benign_shared_nat | benign | 240/240 | 240 | 0 |
| legacy_channel | stale_service_credential | benign | 240/240 | 240 | 0 |
| legacy_channel | missing_ip_benign | benign | 240/240 | 240 | 0 |
| legacy_channel | benign_account_multiple_ips | benign | 240/240 | 240 | 0 |
| legacy_channel | password_reset_typos | benign | 240/240 | 240 | 0 |
| current_source_ip | slow_password_spray | attack | 0/240 | 0 | 240 |
| current_source_ip | low_rate_distributed | attack | 0/240 | 0 | 240 |
| current_source_ip | private_ip_targeted | attack | 0/240 | 0 | 240 |
| current_source_ip | fast_benign_shared_nat | benign | 240/240 | 240 | 0 |
| current_source_ip | stale_service_credential | benign | 240/240 | 240 | 0 |
| current_source_ip | missing_ip_benign | benign | 240/240 | 240 | 0 |
| current_source_ip | benign_account_multiple_ips | benign | 0/240 | 0 | 0 |
| current_source_ip | password_reset_typos | benign | 240/240 | 240 | 0 |
| experimental_contextual | slow_password_spray | attack | 0/240 | 0 | 240 |
| experimental_contextual | low_rate_distributed | attack | 0/240 | 0 | 240 |
| experimental_contextual | private_ip_targeted | attack | 240/240 | 0 | 0 |
| experimental_contextual | fast_benign_shared_nat | benign | 240/240 | 240 | 0 |
| experimental_contextual | stale_service_credential | benign | 240/240 | 240 | 0 |
| experimental_contextual | missing_ip_benign | benign | 240/240 | 240 | 0 |
| experimental_contextual | benign_account_multiple_ips | benign | 240/240 | 240 | 0 |
| experimental_contextual | password_reset_typos | benign | 240/240 | 240 | 0 |

## Interpretation

- Fast legitimate shared-NAT failures can resemble password spraying.
- Slow spraying and distributed guessing can stay below short-window thresholds.
- Repeated wrong service credentials and genuine password mistakes are ambiguous without authorization context.
- Private IPs and missing source fields expose different attribution policy choices; no network addresses are contacted.
- Benign source-IP rotation can resemble a distributed attack against one account.
- Equal case prevalence and reused templates make the metrics **illustrative only**.
- This evaluates `Detector.process()` and an offline prototype on synthetic events; it does not test `Store` persistence, Windows collection, or email delivery.

## Research action

Document false positives and false negatives; design a conservative risk-tiered advisory system
with explicit unknown-source handling, authorization enrichment and persistent bounded history.
Keep automatic blocking disabled. Collect independent real evidence before deployment.
