import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinelforge.live_sensor import Sensor


class LiveSensorTests(unittest.TestCase):

    def test_database_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sensor.db"

            with patch.object(
                Sensor,
                "snapshot_processes",
                return_value=set()
            ), patch.object(
                Sensor,
                "snapshot_connections",
                return_value=set()
            ):
                sensor = Sensor(path)
                sensor.db.close()

            self.assertTrue(path.exists())

    def test_telemetry_storage(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sensor.db"

            with patch.object(
                Sensor,
                "snapshot_processes",
                return_value=set()
            ), patch.object(
                Sensor,
                "snapshot_connections",
                return_value=set()
            ):
                sensor = Sensor(path)

            sensor.record({
                "type": "process",
                "name": "notepad.exe",
                "parent": "explorer.exe"
            })

            count = sensor.db.execute(
                "SELECT COUNT(*) FROM telemetry"
            ).fetchone()[0]

            self.assertEqual(count, 1)
            sensor.db.close()


if __name__ == "__main__":
    unittest.main()
