"""SF-15: one permanently undeliverable message must not starve others."""
import smtplib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelforge.__main__ import deliver_channels
from sentinelforge.core import Alert, Store


class NotificationFairnessTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = Store(str(root / 'events.sqlite3'))
        self.addCleanup(self.store.db.close)
        self.store.baseline()
        self.first = self.store.save_alert(Alert('a', 'low', 'Invalid', 'now', []))
        self.second = self.store.save_alert(Alert('b', 'critical', 'Important', 'now', []))
        self.config = {'mode': 'email', 'email_to': 'recipient@example.invalid'}
        self.enterContext(patch('sentinelforge.__main__.config_path', return_value=root / 'config.json'))
        self.enterContext(patch('sentinelforge.__main__.check_config'))

    def state(self, alert_id):
        return self.store.db.execute(
            "SELECT status,attempts FROM notification_state WHERE alert_id=? AND channel='email'",
            (alert_id,)).fetchone()

    def test_invalid_message_does_not_starve_critical_alert(self):
        with patch('sentinelforge.__main__.send', side_effect=[ValueError('invalid header'), None]) as send:
            deliver_channels(self.store, self.config)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.state(self.first), ('permanent_failed', 1))
        self.assertEqual(self.state(self.second), ('sent', 1))
        self.assertEqual(self.store.channel_counts('email'), 0)

    def test_permanent_smtp_recipient_rejection_is_isolated(self):
        rejected = smtplib.SMTPRecipientsRefused({'bad@example.invalid': (550, b'bad recipient')})
        with patch('sentinelforge.__main__.send', side_effect=[rejected, None]):
            deliver_channels(self.store, self.config)
        self.assertEqual(self.state(self.first), ('permanent_failed', 1))
        self.assertEqual(self.state(self.second), ('sent', 1))
        self.assertEqual(self.store.db.execute(
            'SELECT last_error FROM notification_state WHERE alert_id=?', (self.first,)
        ).fetchone()[0], 'SMTPRecipientsRefused')

    def test_transient_smtp_failure_still_pauses_service(self):
        with patch('sentinelforge.__main__.send', side_effect=OSError('offline')) as send:
            deliver_channels(self.store, self.config)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(self.state(self.first), ('failed', 1))
        self.assertIsNone(self.state(self.second))

    def test_stale_owner_cannot_mark_permanent_failure(self):
        claim = self.store.claim_notification('email', now=10, lease_seconds=5)
        self.store.claim_notification('email', now=20, lease_seconds=5)
        self.assertFalse(self.store.finish_notification(claim[0], 'email', claim[2],
                                                        'ValueError', permanent=True))
