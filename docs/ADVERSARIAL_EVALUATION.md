# SentinelForge — adversarial synthetic detection audit

## Purpose

The earlier six-scenario benchmark deliberately separates rapid password spraying from slower benign shared-NAT failures. A detector may score highly simply by exploiting this difference. This second *challenge* set deliberately reverses those convenient assumptions.

## Eight controlled counterexamples

- **Slow spray (positive):** one public source, many users, approximately one attempt every 3.5 minutes.
- **Low-rate distributed guessing (positive):** one user, many public sources, spread over about an hour.
- **Private-subnet targeted burst (positive):** possible attack traffic whose source is a private IP. SentinelForge deliberately avoids high-confidence public-IP attribution here.
- **Fast benign shared NAT (negative):** multiple staff fail to sign in rapidly via a common gateway.
- **Stale service credential (negative):** a service's outdated password repeatedly fails.
- **Missing-IP benign (negative):** many users' events lack source information; `None` is not a verified source identity.
- **Benign single account from multiple egress IPs (negative):** a mobile or proxied user may rotate addresses.
- **Password-reset typos (negative):** repeated nonmalicious mistakes by one user.

All identities, IPs, times, causes, and labels are synthetic. A negative fixture **does not prove** an event was authorized, just as a positive fixture does not prove an attack. These cases demonstrate plausible detector failure modes, not measured production performance or typical traffic prevalence.

## Run

```powershell
python -m unittest discover -s tests -p 'test_adversarial_logon_audit.py' -v
python -m evaluation.adversarial_logon_audit --seeds 30 --repetitions 8 --ci-check --out evaluation/results/adversarial_logon
Get-Content evaluation/results/adversarial_logon/results.md
```

Keep the original 30-seed report unchanged for comparison. `--ci-check` guards the presence and scoring integrity of hard fixtures; it **does not** freeze knowingly incorrect detection behavior as an expected standard. New policy code needs additional independent tests before deployment.

## Research next steps

Record exact false negatives and false positives; decide which cases require external authorization records, asset inventory, source-validation logic, or alert severity reduction. Add bounded persistent multi-key histories, then run restart, replay and adversarial tests on `Store.ingest_batch`. Maintain advisory-only behavior; avoid automatic blocking based on workstation names, private IPs, or synthetic scores. Leave Windows-VM and clean-install validation to the end of the project hardening phase.
