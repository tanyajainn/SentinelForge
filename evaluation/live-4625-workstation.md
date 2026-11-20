# Windows failed-logon collector validation

Date: 2026-11-20
Windows Security event: 4625
Logon audit policy: Success and Failure

A failed sign-in to a local test account produced a Security event with a
usable WorkstationName. SentinelForge fetched the same record by Record ID
and extracted the workstation name.

Result: PASS for live event collection and workstation extraction.
Live failure-to-success correlation: pending.
