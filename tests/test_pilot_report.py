import hashlib
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sentinelforge.core import Alert, Store
from sentinelforge.pilot import pilot_report


class PilotReportTests(unittest.TestCase):
    def test_report_counts_utc_window_without_leaking_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "fixture.db"
            store = Store(str(db))
            for rule, stamp in [
                ("event-4625", "2026-11-12T01:00:00+04:00"),
                ("sentinelforge-self-test", "2026-11-11T00:00:00Z"),
                ("event-4625", "2026-11-12T00:00:00Z"),
                ("event-4625", "invalid"),
            ]:
                store.save_alert(Alert(rule, "high", "private title", stamp,
                                       [{"message": "private evidence"}]))
            store.channel_result(1, "email", "private SMTP error")
            store.record_channel_check("Security", "private channel error")
            store.db.close()
            before = hashlib.sha256(db.read_bytes()).digest()
            day = date(2026, 11, 11)
            html = pilot_report(db, day, day).read_text(encoding="utf-8")
            self.assertIn("1 rule alerts · 1 self-test alerts", html)
            self.assertIn("1 alerts have an unparseable date", html)
            for word in ["failed", "Unrecorded", "Read error", "No recorded check"]:
                self.assertIn(word, html)
            self.assertNotIn("private", html)
            self.assertEqual(before, hashlib.sha256(db.read_bytes()).digest())

    def test_empty_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "empty.db"
            Store(str(db)).db.close()
            report = pilot_report(db, date.today(), date.today()).read_text(encoding="utf-8")
            self.assertIn("0 rule alerts · 0 self-test alerts", report)
