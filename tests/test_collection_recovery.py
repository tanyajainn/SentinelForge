import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinelforge.__main__ import deliver_configured_email, load_config, scan
from sentinelforge.core import Detector, Event, Store


def failed_logon(record):
    return Event('Security', record, 4625, '2026-11-09T09:00:00Z',
                 'test', 'Synthetic failed logon')


class CollectionRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'events.sqlite3'
        self.store = self.connect()

    def connect(self):
        store = Store(str(self.path))
        self.addCleanup(store.db.close)
        return store

    def test_restart_and_overlapping_fetch(self):
        events = [failed_logon(i) for i in range(1, 7)]
        self.store.ingest_batch('Security', events[:4], Detector())
        other = self.connect()
        alerts = other.ingest_batch('Security', events, Detector())
        self.assertEqual([a.evidence[0]['record_id'] for a in alerts], [5])
        self.assertEqual(self.store.ingest_batch('Security', events, Detector()), [])
        self.assertEqual(self.store.counts()[0], 1)
        self.assertEqual(self.store.cursor('Security'), 6)

    def test_retry_after_partial_batch_failure(self):
        self.store.ingest_batch('Security', [failed_logon(1)], Detector(threshold=2))
        batch = [failed_logon(2), failed_logon(3)]
        self.store.db.execute("""CREATE TRIGGER fail_cursor BEFORE INSERT ON cursor
            BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
        detector = Detector(threshold=2)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.ingest_batch('Security', batch, detector)
        self.assertEqual(self.store.cursor('Security'), 1)
        self.assertEqual(self.store.counts()[0], 0)
        self.store.db.execute('DROP TRIGGER fail_cursor')
        self.assertEqual(len(self.store.ingest_batch('Security', batch, detector)), 1)
        self.assertEqual(self.store.cursor('Security'), 3)

    def test_invalid_channel_batch_leaves_other_channels_collecting(self):
        invalid = failed_logon(1)
        invalid.timestamp = 'invalid'
        valid = Event('System', 2, 7045, '2026-11-09T09:00:00Z', 'test', 'New service')
        with patch('sentinelforge.__main__.CHANNELS', ['Security', 'System']), \
             patch('sentinelforge.__main__.fetch', side_effect=[[invalid], [valid]]):
            self.assertEqual(scan(self.store, Detector(), 10, quiet=True), (1, ['Security']))
        self.assertEqual(self.store.cursor('Security'), 0)
        self.assertEqual(self.store.cursor('System'), 2)

    def test_invalid_mail_config_preserves_queue(self):
        self.store.baseline()
        self.store.ingest_batch('Security', [failed_logon(1)], Detector(threshold=1))
        config = self.path.with_name('notifications.json')
        for content in ('{', json.dumps([])):
            config.write_text(content, encoding='utf-8')
            with patch('sentinelforge.__main__.config_path', return_value=config):
                with self.assertRaises(ValueError):
                    load_config()
                deliver_configured_email(self.store)
            self.assertEqual(self.store.channel_counts('email'), 1)
