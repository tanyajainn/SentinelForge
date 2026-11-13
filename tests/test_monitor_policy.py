import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sentinelforge.__main__ import scan
from sentinelforge.channels import format_alert
from sentinelforge.core import Alert, Detector, Event, Store
from sentinelforge.windows import fetch


class MonitorPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'test.db'
        self.store = Store(str(self.path))
        self.addCleanup(self.store.db.close)
        self.store.baseline()

    def make(self, record, event_id=5007, message='Setting A changed'):
        event = Event('Microsoft-Windows-Windows Defender/Operational', record,
                      event_id, '2026-11-08T12:00:00+00:00', 'Defender', message)
        return Detector().process(event)[0]

    def test_duplicates_survive_restart_without_inflating_queue(self):
        self.store.save_alert(self.make(1))
        other = Store(str(self.path))
        try:
            other.save_alert(self.make(2))
            other.save_alert(self.make(3, message='Setting B changed'))
        finally:
            other.db.close()
        self.assertEqual(self.store.counts()[0], 3)
        self.assertEqual(self.store.channel_counts('email'), 2)
        self.assertEqual(self.store.db.execute(
            "SELECT status, attempts FROM notification_state WHERE alert_id=2").fetchone(), ('grouped', 0))

    def test_historical_alert_cannot_group_first_new_email(self):
        history = Store(str(self.path.with_name('previous.db')))
        try:
            history.save_alert(self.make(1))
            history.baseline()
            history.save_alert(self.make(2))
            self.assertEqual([i for i, _ in history.channel_pending('email')], [2])
        finally:
            history.db.close()

    def test_identical_message_eligible_after_hour(self):
        with patch('sentinelforge.core.time.time', side_effect=[50, 3649, 3650]):
            for i in range(3):
                self.store.save_alert(self.make(i))
        self.assertEqual([i for i, _ in self.store.channel_pending('email')], [1, 3])

    def test_high_priority_events_always_eligible(self):
        for event_id in (5001, 5013, 1118):
            for record in (1, 2):
                alert = self.make(record, event_id)
                self.assertEqual(alert.severity, 'high')
                self.store.save_alert(alert)
        self.assertEqual(self.store.channel_counts('email'), 6)

    def test_email_is_traceable_without_raw_evidence(self):
        subject, body = format_alert(self.make(18, message='private account and path'))
        self.assertIn('MEDIUM', subject)
        self.assertIn('old and new', body)
        self.assertIn('event-5007 | record 18', body)
        self.assertNotIn('private account', body)
        self.assertIn('maintenance record', body)
        self.assertLess(len(body), 600)

    def test_self_test_and_legacy_alerts(self):
        subject, body = format_alert(Alert('sentinelforge-self-test', 'info', 'test', 'now', []))
        self.assertIn('TEST', subject)
        self.assertIn('background agent', body)
        self.assertIn('old-rule', format_alert(Alert('old-rule', 'low', 'Legacy', 'now', []))[1])

    def test_unreadable_log_retains_last_good_read_and_cursor(self):
        self.store.advance('Security', 20)
        with patch('sentinelforge.__main__.CHANNELS', {'Security': []}):
            with patch('sentinelforge.__main__.fetch', return_value=[]):
                scan(self.store, Detector(), 100)
            with patch('sentinelforge.__main__.fetch', side_effect=RuntimeError('access denied')):
                self.assertEqual(scan(self.store, Detector(), 100), (0, ['Security']))
        last, error = self.store.db.execute('SELECT last_success, error FROM channel_health').fetchone()
        self.assertTrue(last)
        self.assertEqual(error, 'access denied')
        self.assertEqual(self.store.cursor('Security'), 20)

    def test_collector_propagates_subprocess_error(self):
        result = SimpleNamespace(returncode=1, stderr='access denied', stdout='')
        with patch('sentinelforge.windows.subprocess.run', return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError, 'access denied'):
                fetch('Security', 0)
        self.assertIn('NoMatchingEventsFound', run.call_args.args[0][-1])

