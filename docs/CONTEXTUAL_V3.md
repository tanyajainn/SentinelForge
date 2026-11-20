# Contextual Detection v3 — opt-in research prototype

## Scope and default behavior

This prototype is **off by default**. Existing Windows monitor, scheduled agent, CLI, emails and SQLite data continue with the previous detector behavior. No automatic blocking, firewall rule or configuration change is performed. To exercise v3 using a *separate disposable database*:

```python
from sentinelforge.core import Store, Detector
store = Store('evaluation/results/contextual_v3_lab.sqlite3', contextual_v3=True)
# store.ingest_batch('Security', synthetic_events, Detector())
```

Never switch a production database to experimental mode without a migration/recovery plan. This prototype emits additional advisory alerts alongside the existing event-4625 alerts; it does **not** replace or suppress existing rules. Its metric must not be confused with an overall production metric.

## Correlation rules

- **v3-account-source-burst:** repeated failures for one public IPv4 + account within the configured window; low severity because service credentials and password-reset mistakes can look identical.
- **v3-password-spray:** multiple distinct accounts from one public IPv4 within up to four minutes; medium severity, not proof of abuse (fast benign shared-NAT traffic remains a counterexample).
- **v3-distributed-guessing:** multiple public IPv4 sources for one account within up to four minutes; medium severity, not proof of abuse (legitimate IP rotation remains a counterexample).

The `minimum diversity` is at least five and rises with the configured threshold. If multiple patterns match on one event, distributed guessing has precedence, then spray, then one-pair burst. Suppress repeated alerts for the same entity/rule within one configured window.

## State and safety properties

- Separate v3 tables store only validated public IPv4, case-folded account identity and event metadata; missing/private/ambiguous attribution is recorded as an aggregate count, **not** fabricated into a source identity.
- History is capped at 5,000 events, and emission metadata at 1,000 entities; expired failures and old emission records are removed on ingest. The cost of bounded operations must be profiled before deployment.
- A monotonic timestamp guard ignores out-of-order event times; those events are counted in diagnostic telemetry. Legitimate clock changes may therefore create false negatives.
- All writes use the caller's SQLite transaction, making cursor advancement, evidence and alert persistence atomic. Replaying the same RecordID must not create new alerts.
- Workstation name and private IP are not used as verified public attribution or authorization to block.
- **No automatic response is permitted** based on these alerts. Keep response separate and gated by human review.

## Validation completed / pending

The new regression suite checks default-off behavior, three patterns, source-quality diagnostics, restart persistence, duplicate suppression, expiration, bounded history, rollback and out-of-order time. Local stub tests or synthetic results do **not** prove Windows collection, enterprise precision, real-world false-positive rates or SMTP delivery.

Next: execute all tests against the actual SentinelForge repository and run both contextual and adversarial benchmark suites unchanged, then design independent authorization-aware fixtures. Only after that decide whether this replaces any legacy rule. Windows VM, real-event replay and fresh-install release validation are intentionally deferred.

## Reproduce

```powershell
python apply_v3.py
python -m unittest discover -s tests -p test_contextual_v3.py -v
python -m unittest discover -s tests -v
python -m evaluation.contextual_benchmark --seeds 3 --repetitions 2 --ci-check --out evaluation/results/contextual_benchmark
python -m evaluation.adversarial_logon_audit --seeds 3 --repetitions 2 --ci-check --out evaluation/results/adversarial_logon
```

**Research warning:** historic synthetic benchmark F1=0.857 and hard negative F1=0.222 pertain to older policies on *constructed scenarios*; this new opt-in implementation has no justified performance score until it is evaluated separately.
