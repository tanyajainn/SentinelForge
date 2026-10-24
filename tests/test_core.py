import tempfile
import unittest
from pathlib import Path
from sentinelforge.core import Event, Detector, Store

class DetectionTests(unittest.TestCase):
    def event(self, eid, record=1):
        return Event('Security', record, eid, '2026-10-24T12:00:00+00:00', 'test', 'synthetic')

    def test_malware(self):
        alerts = Detector().process(self.event(1116))
        self.assertEqual(alerts[0].severity, 'high')

    def test_failed_logon_burst(self):
        detector = Detector(threshold=3)
        self.assertEqual(detector.process(self.event(4625,1)), [])
        self.assertEqual(detector.process(self.event(4625,2)), [])
        self.assertEqual(len(detector.process(self.event(4625,3))), 1)
        self.assertEqual(detector.process(self.event(4625,4)), [])

    def test_store_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(str(Path(d)/'test.db'))
            store.advance('Security', 10)
            store.advance('Security', 9)
            self.assertEqual(store.cursor('Security'), 10)
            store.db.close()

if __name__ == '__main__':
    unittest.main()
