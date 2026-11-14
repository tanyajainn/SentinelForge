import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sentinelforge.legacy_bridge import bridge, convert_alert


class BridgeTests(unittest.TestCase):

    def sample(self):
        return {
            "rule": "event-5001",
            "severity": "high",
            "title": "Defender protection disabled",
            "timestamp": "2026-11-15T10:00:00+00:00",
            "evidence": [],
        }

    def test_control_mapping(self):
        event = convert_alert(1, self.sample())
        self.assertEqual(event.kind, "security_control")
        self.assertEqual(event.attributes["action"], "disabled")

    def test_stable_identity(self):
        a = convert_alert(1, self.sample())
        b = convert_alert(1, self.sample())
        self.assertEqual(a.event_id, b.event_id)

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "legacy.sqlite3"
            target = Path(folder) / "research.sqlite3"

            db = sqlite3.connect(source)
            db.execute(
                "CREATE TABLE alerts (id INTEGER PRIMARY KEY, payload TEXT)"
            )
            db.execute(
                "INSERT INTO alerts VALUES (?, ?)",
                (1, json.dumps(self.sample())),
            )
            db.commit()
            db.close()

            first = bridge(source, target)
            self.assertEqual(first["accepted"], 1)
            self.assertEqual(first["findings"], 1)
            self.assertTrue(first["integrity"]["valid"])

            second = bridge(source, target)
            self.assertEqual(second["accepted"], 0)
            self.assertEqual(second["findings"], 0)


if __name__ == "__main__":
    unittest.main()
