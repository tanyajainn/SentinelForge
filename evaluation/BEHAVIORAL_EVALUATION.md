# Behavioral Fixture Evaluation

## Scope
Seven Windows event types were evaluated using 14 synthetic fixtures:
one labeled suspicious and one labeled authorized per event type.

## Results

| Metric | Count |
|---|---:|
| True positives | 7 |
| False positives | 7 |
| False negatives | 0 |
| True negatives | 0 |

## Interpretation
All 14 fixtures triggered alerts.

The labels were assigned by the test generator. The event messages
differed, but no independently verified behavioral context was supplied.

The resulting 50% fixture precision is not a production accuracy estimate.
This experiment demonstrates that the selected event-ID rules do not
distinguish authorized from unauthorized administrative activity.

## Next validation
Use authorized, labeled Windows event sequences containing contextual
evidence such as actor, target account, account SID, group SID, source,
change authorization, and temporal relationships.

Report per-rule results separately. Measure alert latency during actual
collection, and estimate normal-use alert volume independently.
