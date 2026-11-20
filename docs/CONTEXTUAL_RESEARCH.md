# Context-aware logon detection — research workstream

## Research question
Can account + public-IP + time-window relationships reduce synthetic shared-NAT false positives and detect synthetic multi-source brute force compared with a channel-wide threshold or SentinelForge's existing per-source failed-logon rule?

## Three compared policies
1. **Legacy channel-only**, reconstructed strictly as an experimental comparison (not deployed when a source IP is present).
2. **Current source-IP**, the existing `Detector.process` invoked on real `Event` objects built from synthetic fixtures. This intentionally tests current behavior, not a rewrite.
3. **Experimental contextual**, isolated inside `evaluation/contextual_benchmark.py`. It checks: repeated failures for one (IP, account) pair; many accounts from one public IP within up to 4 minutes; many public IPs for one account within up to 4 minutes. **Never deploy this experimental policy without separate review and Windows replay validation.**

Synthetic positive fixtures: single-pair targeted brute force, password spray (1–2 failures each for 12 usernames from one IP), and distributed brute force (one user with 12 source IPs). Synthetic negative fixtures: isolated mistakes, shared-NAT failures across users over ~20 minutes, and repeated stale service credentials. The last is an intentionally hard negative. These are assumptions about cause, not event-log proof of user intent.

## Preregistered experiment
Sweep 3, 5 and 8 failures and 5, 10 and 20 minutes; 30 reproducibly seeded variations x 8 repetitions per fixture. Use each same input fixture for all policies. Calculate per-seed precision, recall, F1 (mean and sample SD), aggregate confusion matrices, and scenario-specific errors. Keep evaluation policy definitions, fixed seed list and negative fixtures disclosed, so a change cannot quietly cherry-pick only easy examples.

## Operational and ethical limits
- There is **no attack execution** and no privileged OS modification in these fixtures.
- `Event` objects contain made-up account names and public IPv4 strings; no traffic is sent to those addresses.
- One binary decision is scored per scenario episode, not per event, so these values cannot estimate alert volume.
- Episode labels are constructed, the distribution is balanced, and fixture templates are reused across seeds. SD measures sensitivity to this generator, **not** population uncertainty.
- Timing separates the intentionally rapid spray from the intentionally scattered shared-NAT fixture. A slow spray and fast benign failures will defeat these synthetic assumptions.
- Stale service credentials remain a false-positive challenge without authorization/context evidence. Systematic false positives are expected; no production performance claim is justified.
- A production detector would also need persistent group state across restarts, per-account and per-IP limits, memory cap, event ordering checks, unavailable/ambiguous source handling and independent data validation. None is introduced by this offline experiment.
- The CI regression check asserts only fixture-specific expectations for the **experimental** policy, not a minimum real-world accuracy or a claim that current implementation is worse on all datasets.

## Run

```powershell
python -m unittest discover -s tests -p "test_contextual_benchmark.py" -v
python -m evaluation.contextual_benchmark --seeds 30 --repetitions 8 --ci-check --out evaluation/results/contextual_benchmark
```

Read the generated `results.md` (all 27 sweeps) and `results.json` (per-seed metrics), and cite the experiment parameters, output path and commit SHA in your paper. Keep this distinct from the pre-existing six-scenario logon benchmark and historical 8-seed release audit.

## Next phases (deferred by project owner)
Use independently sourced public EVTX Windows event sets or a disposable Windows VM to recheck logs and event field coverage. Record edition, audit settings, SID, source-IP availability and licenses for public corpora. Only after passing those tests should the experimental detector be considered for product integration and a clean-install release.
