import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinelforge.__main__ import scan
from sentinelforge.core import Store, Detector, Event
from sentinelforge.windows import EventBatch


def event(n):
    return Event('Security', n, 4625, '2026-11-17T08:00:00Z', 'test', 'failed login')


class DiscontinuityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = Store(str(Path(temp.name) / 'events.sqlite3'))
        self.addCleanup(self.store.db.close)
        self.store.ingest_batch('Security', [event(100), event(101)], Detector(threshold=2))

    def test_reset_rebases_and_ingests_new_records(self):
        batches = [EventBatch([], oldest=1, newest=4),
                   EventBatch([event(1), event(2)], oldest=1, newest=4)]
        with patch('sentinelforge.__main__.CHANNELS', ['Security']), \
             patch('sentinelforge.__main__.fetch', side_effect=batches) as fetch:
            count, failed = scan(self.store, Detector(threshold=2), 50, True)
        self.assertEqual((count, failed), (1, []))
        self.assertEqual(fetch.call_args_list[1].args[:2], ('Security', 0))
        self.assertEqual(self.store.cursor('Security'), 2)
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule='monitor-log-discontinuity'"
        ).fetchone()[0], 1)

    def test_retention_gap_emits_alert_without_cursor_reset(self):
        result = self.store.reconcile_log_bounds('Security', 101, 110, 120)
        self.assertEqual(result, 'retention-gap')
        self.assertEqual(self.store.cursor('Security'), 101)
        self.assertEqual(self.store.reconcile_log_bounds('Security', 101, 110, 120), 'retention-gap')
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule='monitor-log-discontinuity'"
        ).fetchone()[0], 1)

    def test_normal_progress_does_not_generate_gap(self):
        self.assertEqual(self.store.reconcile_log_bounds('Security', 101, 90, 110), 'ok')
        self.assertEqual(self.store.db.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule='monitor-log-discontinuity'"
        ).fetchone()[0], 0)

    def test_stale_cursor_cannot_reset_another_writer(self):
        self.assertEqual(self.store.reconcile_log_bounds('Security', 99, 1, 4), 'stale')
        self.assertEqual(self.store.cursor('Security'), 101)

    def test_log_reset_does_not_erase_historical_alerts(self):
        prior = self.store.counts()[0]
        self.assertEqual(self.store.reconcile_log_bounds('Security', 101, 1, 4), 'reset')
        self.assertEqual(self.store.cursor('Security'), 0)
        self.assertEqual(self.store.counts()[0], prior + 1)
