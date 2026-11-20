# ATT&CK mapping review — tentative associations, not incident verdicts

Date checked: 2026-11-20. Sources: MITRE ATT&CK Enterprise technique pages below.

| Windows Event IDs | ATT&CK candidate | Interpretation and constraint |
|---|---|---|
| 1102 | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Clear Windows Event Logs; current MITRE ID as of 2026. Do **not** revert to the older T1070.001 solely from historic guides |
| 4625 | [T1110](https://attack.mitre.org/techniques/T1110/) | Repeated authentication failures are possible brute force; a single failure proves nothing |
| 4625 across many accounts at one source | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password spraying is a *behavioral inference*, not an automatic mapping for every 4625 |
| 4697 / 7045 | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service installation; may also be routine administration |
| 4698 | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled task creation; may be benign |
| 4720 | [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account. Refine to [T1136.001](https://attack.mitre.org/techniques/T1136/001/) only when demonstrably a local account |
| 4728 / 4732 | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation / membership changes. Group SID and authorized-change context required |
| 4719 | Under review | Audit policy changed, could support defense-impairment investigation; not necessarily disabling logs |
| 4722 / 4726 / 4740 | Under review | Account enable/delete/lockout; don't assign adversary technique without activity context |
| 4624 | No standalone mapping | Successful sign-in is intentionally suppressed as a standalone alert |
| 1116 / 1117 / 1118 | No event-only mapping | Defender detections/remediation describe product observations and outcomes, not a unique adversary technique |
| 5001 / 5007 / 5013 | Under review | Configuration changes, tampering protections and allowed updates require field-level context |

Do **not** fill every blank ATT&CK cell by guessing. Instead, document why a rule has no responsible event-only mapping. Distinguish a possible tactic from a verified incident, and store the ATT&CK version and review date. Cross-check new technique revisions before publishing an academic mapping table.
