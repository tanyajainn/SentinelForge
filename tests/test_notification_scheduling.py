"""Regression tests: durable per-alert retry scheduling (Batch 6)."""
import tempfile
import unittest
from pathlib import Path
from sentinelforge.core import Store, Alert


class NotificationSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'events.sqlite3'
        self.a = Store(str(self.path))
        self.addCleanup(self.a.db.close)
        self.a.baseline()
        self.first = self.a.save_alert(Alert('one','low','First','now',[]))
        self.second = self.a.save_alert(Alert('two','critical','Second','now',[]))

    def test_deferred_failure_does_not_starve_later_alert(self):
        first = self.a.claim_notification('email', now=100)
        self.assertEqual(first[0], self.first)
        self.assertTrue(self.a.finish_notification(self.first, 'email', first[2],
                                                   'offline', retry_after=400))
        later = self.a.claim_notification('email', now=101)
        self.assertEqual(later[0], self.second)
        self.assertTrue(self.a.finish_notification(self.second, 'email', later[2]))
        self.assertIsNone(self.a.claim_notification('email', now=399))
        self.assertEqual(self.a.claim_notification('email', now=400)[0], self.first)

    def test_retry_deadline_survives_restart(self):
        claim = self.a.claim_notification('email', now=100)
        self.a.finish_notification(self.first, 'email', claim[2], 'offline', retry_after=500)
        b = Store(str(self.path))
        self.addCleanup(b.db.close)
        second = b.claim_notification('email', now=300)
        self.assertEqual(second[0], self.second)
        b.finish_notification(self.second,'email', second[2])
        self.assertIsNone(b.claim_notification('email', now=499))
        self.assertEqual(b.claim_notification('email', now=500)[0], self.first)

    def test_retry_limit_is_persistent_and_terminal(self):
        for attempt in range(3):
            claim = self.a.claim_notification('email', now=100+attempt*10)
            self.assertEqual(claim[0], self.first)
            self.assertTrue(self.a.finish_notification(
                self.first, 'email', claim[2], 'offline',
                retry_after=105+attempt*10, max_attempts=3))
        row = self.a.db.execute(
            "SELECT status,attempts,next_attempt FROM notification_state "
            "WHERE alert_id=? AND channel='email'", (self.first,)).fetchone()
        self.assertEqual(row, ('exhausted', 3, None))
        self.assertEqual(self.a.claim_notification('email', now=999)[0], self.second)

    def test_stale_owner_cannot_change_retry_schedule(self):
        old = self.a.claim_notification('email', now=100, lease_seconds=5)
        fresh = self.a.claim_notification('email', now=110, lease_seconds=5)
        self.assertEqual(fresh[0], self.first)
        self.assertFalse(self.a.finish_notification(
            self.first, 'email', old[2], 'offline', retry_after=1000))
        self.assertTrue(self.a.finish_notification(self.first,'email',fresh[2]))
        self.assertIsNone(self.a.db.execute(
            'SELECT next_attempt FROM notification_state WHERE alert_id=?',
            (self.first,)).fetchone()[0])

    def test_invalid_retry_deadline_rejected(self):
        claim = self.a.claim_notification('email', now=100)
        for bad in (-1, float('nan'), float('inf'), 'later', True):
            with self.assertRaises(ValueError):
                self.a.finish_notification(self.first, 'email', claim[2],
                                           'offline', retry_after=bad)
        self.assertTrue(self.a.finish_notification(self.first, 'email', claim[2]))
