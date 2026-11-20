"""End-to-end opt-in SQLite v3 state tests; no OS mutations or networking."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sentinelforge.core import Detector, Event, Store
from sentinelforge import contextual_v3 as v3

T0 = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)


def failure(record, seconds, user='alice', ip='8.8.8.8', domain='LAB'):
    return Event('Security', record, 4625, (T0 + timedelta(seconds=seconds)).isoformat(),
                 'SyntheticTest', 'Synthetic failed logon', source_ip=ip,
                 target_username=user, target_domain=domain, logon_type=3)


class V3IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbpath = str(Path(self.tmp.name) / 'alerts.sqlite3')
        self.store = Store(self.dbpath, contextual_v3=True)
        self.detector = Detector(threshold=5, window_minutes=10)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def ingest(self, *events):
        return self.store.ingest_batch('Security', events, self.detector)

    def v3hits(self, alerts, rule=None):
        return [a for a in alerts if a.rule.startswith('v3-') and
                (rule is None or a.rule == rule)]

    def restart(self):
        self.store.db.close()
        self.store = Store(self.dbpath, contextual_v3=True)
        self.detector = Detector(threshold=5, window_minutes=10)

    def test_default_off(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / 'default.db'))
            try:
                alerts = store.ingest_batch('Security', [failure(i, i * 10) for i in range(1, 6)], Detector())
                self.assertFalse([x for x in alerts if x.rule.startswith('v3-')])
                self.assertIsNone(store.db.execute("SELECT name FROM sqlite_master WHERE name='v3_failure_evidence'").fetchone())
            finally:
                store.db.close()

    def test_targeted_burst_low_advisory(self):
        alerts = self.ingest(*(failure(i, i * 10) for i in range(1, 6)))
        hits = self.v3hits(alerts, 'v3-account-source-burst')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, 'low')
        self.assertFalse(hits[0].evidence[0]['automatic_blocking_allowed'])

    def test_spray_distinct_accounts(self):
        alerts = self.ingest(*(failure(i, i * 10, user=f'user_{i}') for i in range(1, 7)))
        hits = self.v3hits(alerts, 'v3-password-spray')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, 'medium')
        self.assertEqual(hits[0].evidence[0]['matched_count'], 5)

    def test_distributed_distinct_ips(self):
        alerts = self.ingest(*(failure(i, i * 10, ip=f'9.9.9.{i}') for i in range(1, 7)))
        hits = self.v3hits(alerts, 'v3-distributed-guessing')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, 'medium')

    def test_unknown_private_sources_not_summed(self):
        events = [failure(i, i * 10, user=f'user_{i}', ip=None if i % 2 else '10.0.0.8')
                  for i in range(1, 13)]
        self.assertFalse(self.v3hits(self.ingest(*events)))
        statuses = dict(self.store.db.execute("SELECT status,count FROM v3_source_quality WHERE channel='Security'"))
        self.assertEqual(statuses.get('missing_source'), 6)
        self.assertEqual(statuses.get('unverifiable_source'), 6)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM v3_failure_evidence').fetchone()[0], 0)

    def test_persist_restart_duplicate_idempotent(self):
        self.ingest(*(failure(i, i * 10) for i in range(1, 4)))
        self.restart()
        alerts = self.ingest(failure(4, 40), failure(5, 50))
        self.assertEqual(len(self.v3hits(alerts, 'v3-account-source-burst')), 1)
        self.assertEqual(self.ingest(failure(5, 50)), [])
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM alerts WHERE rule='v3-account-source-burst'").fetchone()[0], 1)

    def test_out_of_order_event_is_not_correlated(self):
        self.ingest(failure(1, 100), failure(2, 110))
        self.assertFalse(self.v3hits(self.ingest(failure(3, 10), failure(4, 20), failure(5, 30))))
        flags = dict(self.store.db.execute('SELECT status,count FROM v3_source_quality'))
        self.assertEqual(flags['out_of_order_event_time'], 3)

    def test_window_expires(self):
        events = [failure(i, i*660) for i in range(1, 7)]
        self.assertFalse(self.v3hits(self.ingest(*events)))

    def test_bounded_rows(self):
        with patch.object(v3, 'MAX_FAILURE_ROWS', 8):
            self.ingest(*(failure(i, i, user=f'user_{i}', ip=f'9.9.9.{i}') for i in range(1, 21)))
        self.assertLessEqual(self.store.db.execute('SELECT COUNT(*) FROM v3_failure_evidence').fetchone()[0], 8)

    def test_rollback_on_bad_channel(self):
        good = failure(1, 5)
        bad = failure(2, 10)
        bad.channel = 'System'
        with self.assertRaises(ValueError):
            self.ingest(good, bad)
        self.assertEqual(self.store.cursor('Security'), 0)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM v3_failure_evidence').fetchone()[0], 0)

    def test_cooldown_suppresses_duplicate_burst(self):
        alerts = self.ingest(*(failure(i, i * 10) for i in range(1, 12)))
        self.assertEqual(len(self.v3hits(alerts, 'v3-account-source-burst')), 1)


if __name__ == '__main__':
    unittest.main()
