"""Concurrency and crash-recovery checks for SF-13 delivery leases."""
import tempfile
import unittest
from pathlib import Path
from sentinelforge.core import Alert, Store

class OutboxLeaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / 'events.sqlite3')
        self.a = Store(db)
        self.b = Store(db)
        self.addCleanup(self.a.db.close)
        self.addCleanup(self.b.db.close)
        self.a.baseline()
        self.id = self.a.save_alert(Alert('test','high','Example','2026-11-17T00:00:00Z',[]))

    def test_competing_workers_cannot_claim_same_row(self):
        first = self.a.claim_notification('email', now=100)
        self.assertEqual(first[0], self.id)
        self.assertIsNone(self.b.claim_notification('email', now=101))
        self.assertTrue(self.a.finish_notification(self.id,'email',first[2]))
        self.assertIsNone(self.b.claim_notification('email', now=102))

    def test_expiry_reclaims_and_stale_owner_cannot_ack(self):
        first = self.a.claim_notification('email', lease_seconds=20, now=100)
        self.assertIsNone(self.b.claim_notification('email', now=119))
        second = self.b.claim_notification('email', now=120)
        self.assertEqual(second[0], self.id)
        self.assertNotEqual(first[2],second[2])
        self.assertFalse(self.a.finish_notification(self.id,'email',first[2]))
        self.assertTrue(self.b.finish_notification(self.id,'email',second[2]))
        self.assertIsNone(self.a.claim_notification('email',now=121))

    def test_failed_send_remains_eligible(self):
        first = self.a.claim_notification('email',now=100)
        self.assertTrue(self.a.finish_notification(self.id,'email',first[2],'network outage'))
        second = self.b.claim_notification('email',now=101)
        self.assertEqual(second[0],self.id)
        self.assertTrue(self.b.finish_notification(self.id,'email',second[2]))
        row = self.a.db.execute("SELECT status,attempts FROM notification_state WHERE alert_id=?",(self.id,)).fetchone()
        self.assertEqual(row,('sent',2))

    def test_unbaselined_store_does_not_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = Store(str(Path(tmp)/'new.sqlite3'))
            try:
                with self.assertRaises(RuntimeError):
                    other.claim_notification('email')
            finally:
                other.db.close()

if __name__ == '__main__':
    unittest.main()
