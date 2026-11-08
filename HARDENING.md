# SentinelForge hardening candidate

Built from the root Python project at tanyajainn/SentinelForge commit 22234b6. The bundled files are a complete build kit for this candidate. Your existing installation and your GitHub repository change only when you apply the update yourself. Do not copy your SQLite database, credentials or built binaries into a public repo.

## Apply to an existing installation

1. Extract the ZIP into a new folder. Open normal Windows PowerShell 5.1 there. Run `python -m unittest discover -s tests -v` and `python -m evaluation.replay`. Read the build script, then run `.\build-windows.ps1` from this ordinary window. Wait for both smoke tests to pass. If a downloaded script is blocked under RemoteSigned, review that individual script and use `Unblock-File -LiteralPath .\build-windows.ps1`. Build inputs, Python and the installed build dependencies must be trusted.
2. Review `update-installed.ps1`. Open Windows PowerShell 5.1 as administrator using the same Windows account that owns your existing task. Change directory to the extracted kit and run `.\update-installed.ps1`. If necessary under RemoteSigned, unblock that individual reviewed script. The updater installs both executables in a fresh administrator-owned directory beneath Program Files. Their names are stable within each version. It keeps prior builds and changes the scheduled task to run with limited privileges. It leaves the configured mailbox, baseline and database in the user's profile. If an update stops partway, inspect the printed error and task definition before retrying. An already-switched task remains limited.
3. Return to the ordinary PowerShell window. Run `.\verify-install.ps1`. If necessary under RemoteSigned, unblock this individual reviewed script. Check for a running limited task, restricted ACLs, and a recent successful read for Security, System and Defender Operational. Allow one scan cycle for status to populate. If a log is unreadable, inspect its read permissions for the task account; consider the local Event Log Readers group where appropriate and sign out and back in after a membership change. Check policy for the specific log. Re-run the verifier. Keep the task limited.
4. Get the protected CLI from the task action in the **ordinary** window:

       $agent = (Get-ScheduledTask -TaskName 'SentinelForge Security Monitor').Actions[0].Execute
       $cli = Join-Path (Split-Path $agent) 'SentinelForge.exe'
       & $cli status
       & $cli self-test

   Confirm inbox receipt and verify one approved benign Windows event against its record ID and SQLite alert. The older one-word command may still point to the old CLI. Use the path above. Avoid launching the retired user-writable executables as administrator.
5. For a first installation only, run the packaged CLI's setup in an ordinary window to establish credentials and a limited per-user task, then use steps 2–4 for protected deployment. Always use the root build kit. The historical nested release snapshot from the upstream repository predates these changes.

## Notification policy

Severity measures review priority. It does not estimate the probability of compromise. Security event 4720 gets high priority because a new account changes access; legitimate account creation triggers the same rule. Event 5001 gets high priority because Defender explicitly reported loss of real-time protection. Event 5013 gets high priority because a protected configuration change was attempted and blocked. Event 1102 gets critical priority because clearing the audit log removes local evidence. Failed sign-ins trigger a high alert only at the configured burst threshold. Each non-test email contains a priority and event title in the subject, followed by a review action, event time and local record reference. Email omits raw evidence.

For event 5007 only, the first eligible change gets a notification. The monitor stores every qualifying alert locally and marks identical repeats as grouped during the next 60 minutes of processing time. Different messages remain eligible immediately. Grouped alerts have zero email attempts and appear as grouped in the CSV export. Records filtered by the existing detector never enter the alert table. Existing queued alerts keep their eligibility. One-time grouping is machine-local and does not guarantee exactly-once SMTP delivery.

Microsoft event definitions: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus

## Evaluation and acceptance

Run `python -m evaluation.replay` from the project root. The eight synthetic Defender records include identical repeats, a distinct configuration change, loss of real-time protection, a blocked change and a remediation failure. The label means “deserves its own email under the declared policy.” The comparison models the previous event-ID mapping on those inputs. It counts queue eligibility; no mail leaves the machine. In the candidate, eight alerts were stored, five selected for email, three grouped. The previous mapping selects six for email, including three redundant notifications, and misses two labeled events. This is a regression fixture, not an estimate of attack detection accuracy.

For an independent study, pre-register the primary endpoint as immediate emails per 100 eligible records, with recall of analyst-labeled actionable episodes as a co-primary endpoint. Use separate tuning and held-out Windows VM sessions. Record Windows edition, Defender engine version, polling interval, audit policy and channel ACLs. Replay the same traces under both policies. Have two reviewers label expected notifications without seeing either policy's output; report disagreements, per-session rates and sample sizes. For latency, pair each event record ID with alert insertion, SMTP submission and observed inbox arrival. Report median and p95 with the denominator, including missing deliveries separately. For failure cases, test denied channel access, app restart during a repeat burst, and a temporary SMTP outage. Archive redacted traces, exact commit and test commands. Do not disable protection on a primary laptop for this experiment.

Windows-specific acceptance is pending. In a disposable Windows environment validate fresh installation and migration, ordinary-user write denial, both tasks' permissions before and after migration, logon startup, all three channel reads, one real event-to-inbox correlation, an interrupted update and a repeat update. Record observed outcomes before making deployment or accuracy claims.
