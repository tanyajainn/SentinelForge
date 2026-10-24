import csv
import tempfile
import unittest
from pathlib import Path

from sentinelforge.core import Store, Alert
from sentinelforge.reporting import export_csv, spreadsheet_safe


class ReportingTests(unittest.TestCase):

    def test_spreadsheet_formula_protection(self):
        self.assertEqual(
            spreadsheet_safe("=HYPERLINK(...)"),
            "'=HYPERLINK(...)"
        )

    def test_export_preserves_database(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "alerts.sqlite3"
            output = Path(folder) / "export.csv"

            store = Store(str(database))

            store.save_alert(Alert(
                rule="event-1116",
                severity="high",
                title="Test detection",
                timestamp="2026-10-25T00:00:00+00:00",
                evidence=[{
                    "channel": "Security",
                    "event_id": 1116,
                    "record_id": 42,
                    "timestamp": "2026-10-25T00:00:00+00:00",
                    "provider": "test",
                    "message": "=DANGEROUS()"
                }]
            ))

            before = store.counts()[0]
            store.db.close()

            result, count = export_csv(database, output)

            self.assertEqual(count, 1)
            self.assertTrue(result.exists())

            with result.open(encoding="utf-8-sig", newline="") as f:
                row = next(csv.DictReader(f))

            self.assertEqual(row["event_id"], "1116")
            self.assertEqual(row["record_id"], "42")
            self.assertEqual(row["email_status"], "not_recorded")
            self.assertEqual(row["evidence_message"], "'=DANGEROUS()")

            store = Store(str(database))
            self.assertEqual(store.counts()[0], before)
            store.db.close()


if __name__ == "__main__":
    unittest.main()
