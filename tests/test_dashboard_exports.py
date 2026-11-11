from contextlib import closing
import csv
import sqlite3
import tempfile
import unittest
from pathlib import Path

from dashboard import render
from sentinelforge.core import Store
from sentinelforge.reporting import export_csv


class DashboardExportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.db = self.folder / "custom #1.db"
        store = Store(str(self.db))
        with store.db:
            for payload in ["null", "[]", '{"evidence":{"record_id":42}}']:
                store.db.execute("INSERT INTO alerts(timestamp,severity,rule,payload) VALUES(?,?,?,?)",
                                 ("2026-11-11", "high", "local-demo", payload))
        store.db.close()

    def test_custom_dashboard_uses_matching_data_and_log(self):
        (self.folder / "monitor.log").write_text("Scan complete: demo", encoding="utf-8")
        page = render(self.db)
        self.assertIn("Scan complete: demo", page)
        self.assertIn("local-demo", page)
        with self.assertRaises(FileNotFoundError):
            render(self.folder / "missing.db")

    def test_unusual_payloads_preserve_alert_rows(self):
        output, count = export_csv(self.db)
        self.assertEqual(count, 3)
        with output.open(encoding="utf-8-sig", newline="") as stream:
            self.assertEqual([r["record_id"] for r in csv.DictReader(stream)], ["", "", "42"])

    def test_failed_export_preserves_previous_report(self):
        output = self.folder / "report.csv"
        output.write_bytes(b"previous report")
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("DROP TABLE notification_state")
        files = set(self.folder.iterdir())
        with self.assertRaises(sqlite3.Error):
            export_csv(self.db, output)
        self.assertEqual(output.read_bytes(), b"previous report")
        self.assertEqual(files, set(self.folder.iterdir()))

    def test_cannot_export_over_database_or_sidecar(self):
        before = self.db.read_bytes()
        for target in [self.db, Path(str(self.db) + "-wal")]:
            with self.assertRaises(ValueError):
                export_csv(self.db, target)
        self.assertEqual(before, self.db.read_bytes())
