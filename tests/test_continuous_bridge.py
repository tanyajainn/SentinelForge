import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sentinelforge.continuous_bridge import synchronize


class ContinuousBridgeTests(unittest.TestCase):

    def test_incremental_import_and_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "legacy.db"
            target = Path(folder) / "evidence.db"

            db = sqlite3.connect(source)
            db.execute(
                "CREATE TABLE alerts "
                "(id INTEGER PRIMARY KEY, payload TEXT)"
            )

            def insert_alert(identifier):
                payload = {
                    "rule": "event-5001",
                    "severity": "high",
                    "title": "Protection disabled",
                    "timestamp": "2026-11-15T10:00:00+00:00",
                    "evidence": [],
                }
                db.execute(
                    "INSERT INTO alerts VALUES (?,?)",
                    (identifier, json.dumps(payload))
                )
                db.commit()

            insert_alert(1)

            first = synchronize(source, target)
            self.assertEqual(first["accepted"], 1)
            self.assertEqual(first["findings"], 1)

            second = synchronize(source, target)
            self.assertEqual(second["accepted"], 0)

            insert_alert(2)

            third = synchronize(source, target)
            self.assertEqual(third["accepted"], 1)
            self.assertEqual(third["total_evidence"], 2)
            self.assertTrue(third["integrity_valid"])

            db.close()

    def test_missing_source(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                synchronize(
                    Path(folder) / "missing.db",
                    Path(folder) / "evidence.db"
                )


if __name__ == "__main__":
    unittest.main()
