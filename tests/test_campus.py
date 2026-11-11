import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sentinelforge.channels import format_alert
from sentinelforge.core import Detector, Event, Store
from sentinelforge.fleet import snapshot, fleet_report
from sentinelforge.windows import CHANNELS


class CampusTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        db = self.folder / "test.db"
        store = Store(str(db))
        try:
            for i, eid in enumerate([4698, 4722, 4726, 4740], 1):
                self.assertIn(eid, CHANNELS["Security"])
                event = Event("Security", i, eid, "2026-11-11T12:00:00Z", "fixture", "PRIVATE")
                alert, = store.ingest_batch("Security", [event], Detector())
                subject, body = format_alert(alert)
                self.assertIn(alert.title, subject)
                self.assertIn(f"record {i}", body)
                self.assertNotIn("PRIVATE", body)
                self.assertIn("If ", body)
        finally:
            store.db.close()
        day = date(2026, 11, 11)
        self.data = snapshot(db, "LAB-1", day, day)

    def test_hundred_endpoint_report(self):
        for i in range(100):
            (self.folder / f"{i}.json").write_text(json.dumps(dict(self.data, endpoint=f"LAB-{i}")))
        result = fleet_report(self.folder)
        self.assertIn("100 reporting endpoints", result)
        self.assertIn("Scheduled task created</td><td>100</td>", result)
        self.assertIn("no check recorded", result)
        self.assertNotIn("PRIVATE", result)

    def test_duplicate_and_different_period_are_rejected(self):
        (self.folder / "a.json").write_text(json.dumps(self.data))
        b = self.folder / "b.json"
        b.write_text(json.dumps(dict(self.data, endpoint="lab-1")))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            fleet_report(self.folder)
        b.write_text(json.dumps(dict(self.data, endpoint="LAB-2", end="2026-11-12")))
        with self.assertRaisesRegex(ValueError, "period"):
            fleet_report(self.folder)

    def test_invalid_counts_are_rejected(self):
        (self.folder / "bad.json").write_text(json.dumps(dict(self.data, counts={"other": -2})))
        with self.assertRaisesRegex(ValueError, "counts"):
            fleet_report(self.folder)
