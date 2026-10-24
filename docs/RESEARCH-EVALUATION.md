# SentinelForge Research Evaluation

## Research objective
Evaluate the reliability and limitations of Windows Event Log
detection with persistent Gmail notification delivery.

## Experiments still required

1. Measure true positives, false positives and false negatives.
2. Calculate precision, recall and F1 score.
3. Measure event-to-email notification latency.
4. Measure CPU, memory and storage consumption.
5. Test recovery after internet disconnection.
6. Test automatic monitoring after Windows restart.
7. Test fresh installation on a clean Windows environment.

## Results

No unperformed experiment is reported as completed.

## Reproducibility

Record Windows edition, version, event auditing settings,
software version, test conditions, sample sizes and raw results.

## Limitations

SentinelForge monitors selected Windows event IDs.
It is not antivirus, a complete EDR, or a guarantee of intrusion detection.
SMTP acceptance is different from confirmed inbox delivery.
