# SentinelForge firewall response: opt-in preview

This is a separate Python module. It does not modify the installed SentinelForge agent, and does not automatically infer source IPs from 4625 aggregate events.

From the development repo root:

```powershell
python -m unittest discover -s tests -v
python -m sentinelforge.response plan --ip 8.8.8.8
python -m sentinelforge.response plan --ip 192.168.1.1
```

The first preview must say DRY RUN ONLY; the second must be rejected. Neither changes firewall rules. **Do not run apply against 8.8.8.8; it is an example, not an attacker.**

Only after independently verifying an actual malicious *public IPv4 address*, use elevated PowerShell and supply a reason and exact confirmation:

```powershell
python -m sentinelforge.response apply --ip ACTUAL_VERIFIED_IP --reason 'Incident case reference' --confirm 'BLOCK ACTUAL_VERIFIED_IP'
python -m sentinelforge.response list
python -m sentinelforge.response rollback --rule ACTUAL_RULE_ID --confirm 'REMOVE ACTUAL_RULE_ID'
```

Rules are inbound-only. Audit records go to `%USERPROFILE%\SentinelForgeData\firewall_response_audit.jsonl`. The module does not guarantee auto-expiry or detect IP spoofing. Use dry-run only until the module is reviewed. The module is not yet included in the PyInstaller CLI, and has no automatic response integration.
