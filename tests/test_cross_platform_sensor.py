import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from sentinelforge.cross_platform_sensor import Sensor

class SensorTests(unittest.TestCase):
    def test_baseline_and_new_events(self):
        proc = [{(10, 100.0)}, {(10, 100.0), (11, 101.0)}, {(11, 101.0)}]
        net = [set(), {(11, '127.0.0.1', 1234, '127.0.0.1', 443)}, set()]
        with tempfile.TemporaryDirectory() as d:
            sensor = Sensor(Path(d) / 'data.sqlite3', lambda: proc.pop(0), lambda: net.pop(0))
            events = sensor.poll()
            self.assertEqual({x['event_type'] for x in events}, {'process_observed','tcp_connection_observed'})
            self.assertEqual(sensor.poll(), [])
            sensor.close()
            db = sqlite3.connect(Path(d) / 'data.sqlite3')
            rows = db.execute('SELECT payload FROM telemetry').fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(json.loads(rows[0][0])['schema_version'], 1)
            db.close()

    def test_permission_error_does_not_create_fake_events(self):
        def denied():
            raise RuntimeError('unavailable')
        with tempfile.TemporaryDirectory() as d:
            sensor = Sensor(Path(d) / 'x.db', denied, lambda: set())
            self.assertEqual(sensor.poll(), [])
            self.assertTrue(sensor.health_errors)
            sensor.close()

if __name__ == '__main__':
    unittest.main()
