import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelforge.attribution import safe_source_ip
from sentinelforge.core import Detector, Event, Store
from sentinelforge.windows import fetch


def ev(i, ip, stamp='2026-11-14T10:00:00Z'):
    return Event('Security', i, 4625, stamp, 'test', 'synthetic', source_ip=ip,
                 target_username='testuser', logon_type=3)


class AttributionTests(unittest.TestCase):
    def test_rejects_non_public_and_multicast(self):
        for ip in ('-', '::1', '127.0.0.1', '192.168.1.2', '224.0.0.1',
                   '255.255.255.255', 'not-an-ip', '8.8.8.8/24'):
            with self.subTest(ip=ip):
                self.assertIsNone(safe_source_ip(ip))
        self.assertEqual(safe_source_ip('8.8.8.8'), '8.8.8.8')

    def test_separate_sources_and_legacy(self):
        d = Detector(threshold=3)
        self.assertFalse(d.process(ev(1, '8.8.8.8')))
        self.assertFalse(d.process(ev(2, '1.1.1.1')))
        self.assertFalse(d.process(ev(3, '8.8.8.8')))
        alerts = d.process(ev(4, '8.8.8.8'))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule, 'event-4625-source')
        self.assertEqual(alerts[0].evidence[0]['source_ip'], '8.8.8.8')
        self.assertFalse(d.process(ev(5, '1.1.1.1')))
        self.assertFalse(d.process(ev(6, '8.8.8.8')))

    def test_state_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'events.db')
            s = Store(path)
            self.assertEqual(s.ingest_batch('Security', [ev(1,'8.8.8.8'),ev(2,'1.1.1.1')], Detector(threshold=2)), [])
            s.db.close()
            s = Store(path)
            alerts = s.ingest_batch('Security', [ev(3,'8.8.8.8')], Detector(threshold=2))
            self.assertEqual(len(alerts), 1)
            self.assertEqual(s.ingest_batch('Security', [ev(3,'8.8.8.8')], Detector(threshold=2)), [])
            s.db.close()

    def test_windows_event_xml_fields(self):
        class R:
            returncode=0
            stderr=''
            stdout='[{"channel":"Security","record_id":1,"event_id":4625,"timestamp":"2026-11-14T10:00:00Z","provider":"test","message":"test","source_ip":"8.8.8.8","target_username":"bob","logon_type":"3"}]'
        with patch('sentinelforge.windows.subprocess.run', return_value=R()) as runner:
            result = fetch('Security',0)
        self.assertEqual(result[0].source_ip,'8.8.8.8')
        self.assertEqual(result[0].logon_type,3)
        command=runner.call_args.args[0][-1]
        self.assertIn("$fields['IpAddress']", command)
        self.assertIn("$fields['TargetUserName']", command)

if __name__ == '__main__':
    unittest.main()
