# Contextual v3 — replay comparison

**Research-only, synthetic cases. Not production precision or recall.**

30 seeds × 8 repetitions per case; threshold 5, window 10 minutes.

Only `v3-` alerts count for v3. Existing v2 alerts also emitted during ingestion are excluded.
The offline prototype is evaluated separately and is not deployed.

## Original Contextual

| Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |
|---|---:|---:|---:|---:|---:|---:|---:|
| current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| opt_in_v3_only | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |

### Per-scenario errors

| Policy | Scenario | Label | Flagged | FP | FN |
|---|---|---|---:|---:|---:|
| current_source_ip | isolated_mistakes | benign | 0/240 | 0 | 0 |
| current_source_ip | shared_nat_benign | benign | 240/240 | 240 | 0 |
| current_source_ip | stale_service_credential | benign | 240/240 | 240 | 0 |
| current_source_ip | targeted_brute_force | attack | 240/240 | 0 | 0 |
| current_source_ip | password_spraying | attack | 240/240 | 0 | 0 |
| current_source_ip | distributed_brute_force | attack | 0/240 | 0 | 240 |
| experimental_contextual | isolated_mistakes | benign | 0/240 | 0 | 0 |
| experimental_contextual | shared_nat_benign | benign | 0/240 | 0 | 0 |
| experimental_contextual | stale_service_credential | benign | 240/240 | 240 | 0 |
| experimental_contextual | targeted_brute_force | attack | 240/240 | 0 | 0 |
| experimental_contextual | password_spraying | attack | 240/240 | 0 | 0 |
| experimental_contextual | distributed_brute_force | attack | 240/240 | 0 | 0 |
| opt_in_v3_only | isolated_mistakes | benign | 0/240 | 0 | 0 |
| opt_in_v3_only | shared_nat_benign | benign | 0/240 | 0 | 0 |
| opt_in_v3_only | stale_service_credential | benign | 240/240 | 240 | 0 |
| opt_in_v3_only | targeted_brute_force | attack | 240/240 | 0 | 0 |
| opt_in_v3_only | password_spraying | attack | 240/240 | 0 | 0 |
| opt_in_v3_only | distributed_brute_force | attack | 240/240 | 0 | 0 |

v3 advisory rule emissions (may exceed episode count): `v3-account-source-burst`=480, `v3-distributed-guessing`=240, `v3-password-spray`=240

## Adversarial Challenge

| Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |
|---|---:|---:|---:|---:|---:|---:|---:|
| current_source_ip | 0 | 960 | 720 | 240 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 |
| experimental_contextual | 240 | 1200 | 480 | 0 | 0.167 ± 0.000 | 0.333 ± 0.000 | 0.222 ± 0.000 |
| opt_in_v3_only | 0 | 960 | 720 | 240 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 |

### Per-scenario errors

| Policy | Scenario | Label | Flagged | FP | FN |
|---|---|---|---:|---:|---:|
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
| opt_in_v3_only | slow_password_spray | attack | 0/240 | 0 | 240 |
| opt_in_v3_only | low_rate_distributed | attack | 0/240 | 0 | 240 |
| opt_in_v3_only | private_ip_targeted | attack | 0/240 | 0 | 240 |
| opt_in_v3_only | fast_benign_shared_nat | benign | 240/240 | 240 | 0 |
| opt_in_v3_only | stale_service_credential | benign | 240/240 | 240 | 0 |
| opt_in_v3_only | missing_ip_benign | benign | 0/240 | 0 | 0 |
| opt_in_v3_only | benign_account_multiple_ips | benign | 240/240 | 240 | 0 |
| opt_in_v3_only | password_reset_typos | benign | 240/240 | 240 | 0 |

v3 advisory rule emissions (may exceed episode count): `v3-account-source-burst`=480, `v3-distributed-guessing`=240, `v3-password-spray`=240

## Limits

- Labels reflect authored fixtures, not independently authenticated malicious/authorized intent.
- Results vary with arbitrary scenario prevalence; no operational false-positive rate is inferred.
- Existing v2 alerts remain active when v3 is opted in; counting both will change user-visible alert volume.
- SQLite `:memory:` matches transaction logic but does not test disk persistence/restart, retention under heavy load or Windows collection.
- Future decision: review false positives by scenario, run disk-backed restart and overlap tests, and only then decide on live rollout.
