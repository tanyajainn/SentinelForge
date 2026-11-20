# SentinelForge contextual 4625 research benchmark

All results below are **synthetic**. Labels are generator assumptions,
not independently validated attacks. The experimental policy is **not deployed**.

Seeds: 30; repetitions per scenario per seed: 8.

| Window | Threshold | Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 5 | 3 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 5 | 3 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 5 | 3 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 5 | 5 | legacy_channel | 720 | 274 | 0 | 446 | 0.725 ± 0.018 | 1.000 ± 0.000 | 0.840 ± 0.012 |
| 5 | 5 | current_source_ip | 480 | 274 | 240 | 446 | 0.637 ± 0.021 | 0.667 ± 0.000 | 0.651 ± 0.011 |
| 5 | 5 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 5 | 8 | legacy_channel | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 5 | 8 | current_source_ip | 480 | 240 | 240 | 480 | 0.667 ± 0.000 | 0.667 ± 0.000 | 0.667 ± 0.000 |
| 5 | 8 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 10 | 3 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 10 | 3 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 10 | 3 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 10 | 5 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 10 | 5 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 10 | 5 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 10 | 8 | legacy_channel | 720 | 478 | 0 | 242 | 0.601 ± 0.004 | 1.000 ± 0.000 | 0.751 ± 0.003 |
| 10 | 8 | current_source_ip | 480 | 478 | 240 | 242 | 0.501 ± 0.004 | 0.667 ± 0.000 | 0.572 ± 0.003 |
| 10 | 8 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 20 | 3 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 20 | 3 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 20 | 3 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 20 | 5 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 20 | 5 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 20 | 5 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |
| 20 | 8 | legacy_channel | 720 | 480 | 0 | 240 | 0.600 ± 0.000 | 1.000 ± 0.000 | 0.750 ± 0.000 |
| 20 | 8 | current_source_ip | 480 | 480 | 240 | 240 | 0.500 ± 0.000 | 0.667 ± 0.000 | 0.571 ± 0.000 |
| 20 | 8 | experimental_contextual | 720 | 240 | 0 | 480 | 0.750 ± 0.000 | 1.000 ± 0.000 | 0.857 ± 0.000 |

## Scenario-level results (10 min, threshold 5)

| Policy | Scenario | Episodes | Flagged | FP | FN |
|---|---|---:|---:|---:|---:|
| legacy_channel | isolated_mistakes | 240 | 0 | 0 | 0 |
| legacy_channel | shared_nat_benign | 240 | 240 | 240 | 0 |
| legacy_channel | stale_service_credential | 240 | 240 | 240 | 0 |
| legacy_channel | targeted_brute_force | 240 | 240 | 0 | 0 |
| legacy_channel | password_spraying | 240 | 240 | 0 | 0 |
| legacy_channel | distributed_brute_force | 240 | 240 | 0 | 0 |
| current_source_ip | isolated_mistakes | 240 | 0 | 0 | 0 |
| current_source_ip | shared_nat_benign | 240 | 240 | 240 | 0 |
| current_source_ip | stale_service_credential | 240 | 240 | 240 | 0 |
| current_source_ip | targeted_brute_force | 240 | 240 | 0 | 0 |
| current_source_ip | password_spraying | 240 | 240 | 0 | 0 |
| current_source_ip | distributed_brute_force | 240 | 0 | 0 | 240 |
| experimental_contextual | isolated_mistakes | 240 | 0 | 0 | 0 |
| experimental_contextual | shared_nat_benign | 240 | 0 | 0 | 0 |
| experimental_contextual | stale_service_credential | 240 | 240 | 240 | 0 |
| experimental_contextual | targeted_brute_force | 240 | 240 | 0 | 0 |
| experimental_contextual | password_spraying | 240 | 240 | 0 | 0 |
| experimental_contextual | distributed_brute_force | 240 | 240 | 0 | 0 |

## Interpretation and threats to validity

- The **legacy** column reproduces a historical channel-wide sliding window as a comparison; it is not the current deployed implementation.
- **Current source-IP** runs the actual `Detector.process()` for synthetic events with public IP addresses. Its grouping can confuse many users behind one NAT and miss one user attacked from many addresses.
- **Experimental contextual** is a research-only policy: same-IP/same-account bursts; many accounts from one IP within four minutes; or many IPs against one account within four minutes. No production detector or SQLite schema was changed by this experiment.
- The shared-NAT fixture is deliberately slow and the spraying fixture deliberately rapid; timing makes these synthetic classes separable, but real attackers can go slowly and benign systems can fail quickly.
- The stale-service fixture remains a likely false positive because authorization state is invisible in event 4625. No model can reliably identify intent from only username, IP and time.
- Seeded variations are repeated samples of **the same synthetic generator**, not 30 independent organizations or an empirical confidence interval. Seed SD does not imply generalization.
- Scoring uses one binary decision per episode. It does not measure alert volume, event capture, end-to-end latency, SMTP delivery or deployed detector restart persistence.
- Scenario prevalence is balanced by design, so synthetic precision does not estimate operational precision. Avoid treating higher F1 as a justification for silent production policy changes.

## Reproduce

```powershell
python -m evaluation.contextual_benchmark --seeds 30 --repetitions 8 --out evaluation/results/contextual_benchmark
```

Use the same windows, thresholds and seeds to compare policies. Keep the test corpus fixed when changing detector code.
