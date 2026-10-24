import tempfile
import unittest
from pathlib import Path
from sentinelforge.core import Store, Detector, Event, Alert

class V02Tests(unittest.TestCase):
    def test_suppress_defender_ui_noise(self):
        e = Event('Microsoft-Windows-Windows Defender/Operational', 1, 5007,
                  '2026-10-24T12:00:00+00:00','Defender','ToastOrSsoTrigger = 0x1')
        self.assertEqual(Detector().process(e), [])

    def test_defender_relevant_change(self):
        e = Event('Microsoft-Windows-Windows Defender/Operational', 1, 5007,
                  '2026-10-24T12:00:00+00:00','Defender','EnableNetworkProtection = 0x0')
        self.assertEqual(len(Detector().process(e)), 1)

    def test_outbox_retry_and_ack(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(str(Path(d)/'alerts.db'))
            a = Alert('test','high','Test','2026-10-24T12:00:00+00:00',[])
            i = s.save_alert(a)
            self.assertEqual(len(s.pending()),1)
            s.delivery_result(i, 'network unavailable')
            self.assertEqual(len(s.pending()),1)
            s.delivery_result(i)
            self.assertEqual(len(s.pending()),0)
            s.db.close()

if __name__ == '__main__': unittest.main()
