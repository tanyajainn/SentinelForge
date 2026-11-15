import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from sentinelforge.__main__ import deliver_channels
from sentinelforge.core import Detector, Event, Store
from sentinelforge.pilot import pilot_report


class DetectionDeliveryTests(unittest.TestCase):
    def test_restart_after_failed_submission(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        db = root / 'events.sqlite3'
        config = {'mode': 'email', 'email_to': 'recipient@example.invalid'}
        self.enterContext(patch.dict(os.environ, {
            'SENTINELFORGE_GMAIL_FROM': 'sender@example.invalid',
            'SENTINELFORGE_GMAIL_APP_PASSWORD': 'fixture',
        }))
        self.enterContext(patch('sentinelforge.__main__.config_path',
                                return_value=root / 'config.json'))
        smtp = self.enterContext(patch('smtplib.SMTP_SSL'))
        submit = smtp.return_value.__enter__.return_value.send_message
        submit.side_effect = [EOFError('interrupted'), None]
        events = [Event('Security', i, 4625, '2026-11-09T09:00:00Z',
                        'fixture', 'Synthetic failed logon') for i in range(1, 6)]

        store = Store(str(db))
        try:
            store.baseline()
            self.assertEqual(len(store.ingest_batch('Security', events, Detector())), 1)
            # Valid JSON with a damaged retry counter must still allow recovery.
            (root / 'smtp_retry_state.json').write_text('{"failures":"broken"}')
            with patch('time.time', return_value=1000):
                deliver_channels(store, config)
            self.assertEqual(store.channel_counts('email'), 1)
        finally:
            store.db.close()

        store = Store(str(db))
        self.addCleanup(store.db.close)
        self.assertEqual(store.ingest_batch('Security', events, Detector()), [])
        with patch('time.time', return_value=1299):
            deliver_channels(store, config)
        self.assertEqual(submit.call_count, 1)
        with patch('time.time', return_value=1300):
            deliver_channels(store, config)
            deliver_channels(store, config)
        self.assertEqual(submit.call_count, 2)
        self.assertEqual(submit.call_args.args[0]['To'], config['email_to'])
        self.assertEqual(store.db.execute(
            "SELECT status, attempts FROM notification_state WHERE channel='email'"
        ).fetchall(), [('sent', 2)])
        day = date(2026, 11, 9)
        report = pilot_report(db, day, day).read_text(encoding='utf-8')
        self.assertIn('1 rule alerts', report)
        self.assertIn('>sent<', report)
