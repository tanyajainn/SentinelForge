# SentinelForge campus review

Student developer: Tanya Jain, RIT Dubai. This release candidate combines local Windows monitoring, plain-text triage emails and aggregate reporting across endpoints.

## Review workflow

1. Run the unit suite and the failed-logon benchmark from the source checkout.
2. On each participating Windows endpoint, choose a unique lab alias and the same inclusive UTC dates. Run the snapshot command below. Use a new destination for each collection. Accept summaries only from known participants.
3. Copy the JSON summaries to a folder on the review computer using the institution's approved transfer method. The summary contains rule counts, dates, a lab alias, last-known channel states and a count of failed email states. Keep raw evidence on the original endpoint.
4. Generate the combined report. Print the HTML to PDF when a fixed copy is needed. Compare the submitted aliases with the intended inventory. To investigate one alert, use the local event reference in its email.
5. Record who reviewed each finding, whether it was expected, and any action taken. This review remains manual.

    python -m unittest discover -s tests
    python -m evaluation.logon_benchmark
    python -m sentinelforge.fleet snapshot --endpoint LAB-01 --from-date 2026-11-01 --to-date 2026-11-11 --out summaries/LAB-01.json
    python -m sentinelforge.fleet report --input summaries --out campus-review.html

## Evidence and limits

The 100-summary regression test checks counting and data handling with generated inputs. Distinct real machines, network collection, inbox arrival, and production throughput require separate trials. Snapshots are unsigned and copied manually. The report rejects duplicate aliases and mismatched reporting periods; it cannot identify a missing machine without an external inventory. Operating-system audit settings, channel access and retention affect coverage. Routine administrative changes can trigger review.

The added Security-channel events cover scheduled task creation (4698), account enablement (4722), account deletion (4726) and account lockout (4740). Domain account events may be recorded on a domain controller. Use Microsoft Learn's Windows security auditing event references when verifying event availability. The failed-logon benchmark evaluates one rule only.

Before a deployment decision, verify clean installation, task startup after sign-in, expected event evidence and inbox receipt on an independently administered Windows machine. Record build revision, endpoint alias, observed results and unresolved issues with the student developer's submission.
