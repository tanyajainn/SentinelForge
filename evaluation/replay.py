"""Run from the source root: python -m evaluation.replay"""
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.core import Detector, Event, Store

# The label is whether this event deserves its own immediate email under the
# stated policy. All cases arrive within one hour of processing time.
TRACE = [
    (5007, 'Setting A: 0 -> 1', True),
    (5007, 'Setting A: 0 -> 1', False),
    (5007, 'Setting A: 0 -> 1', False),
    (5007, 'Setting B: 1 -> 0', True),
    (5007, 'Setting B: 1 -> 0', False),
    (5001, 'Real-time protection stopped', True),
    (5013, 'Tamper protection blocked a change', True),
    (1118, 'Remediation failed', True),
]


def main():
    historical_ids = {1116, 1117, 1118, 5007}
    expected = set()
    previous = set()
    with TemporaryDirectory() as tmp:
        store = Store(str(Path(tmp) / 'replay.db'))
        try:
            store.baseline()
            detector = Detector()
            start = datetime(2026, 11, 8, tzinfo=timezone.utc)
            for record, (event_id, message, should_email) in enumerate(TRACE, 1):
                if should_email:
                    expected.add(record)
                if event_id in historical_ids:
                    previous.add(record)
                event = Event('Microsoft-Windows-Windows Defender/Operational', record,
                              event_id, (start + timedelta(seconds=record)).isoformat(),
                              'Defender', message)
                for alert in detector.process(event):
                    store.save_alert(alert)
            eligible = {a.evidence[-1]['record_id'] for _, a in store.channel_pending('email')}
            print(f'{len(TRACE)} synthetic records, {store.counts()[0]} stored by candidate')
            print('policy                 emails    TP    FP    FN')
            for name, found in [('original rule mapping', previous), ('candidate', eligible)]:
                print(f'{name:22} {len(found):5} {len(found & expected):5} '
                      f'{len(found - expected):5} {len(expected - found):5}')
            if eligible != expected:
                raise SystemExit('Candidate failed its labelled trace.')
        finally:
            store.db.close()


if __name__ == '__main__':
    main()
