import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sf_research.model import Event, host_token
from sf_research.evidence import Ledger
from sf_research.detection import Correlator
from sf_research.cli import ingest

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(number, kind='process', attributes=None, host='host-a', second=0):
    return Event.parse({'event_id': f'e{number}', 'timestamp': (BASE + timedelta(seconds=second)).isoformat(),
        'host_id': host, 'os': 'synthetic', 'kind': kind, 'source': 'unit-test', 'attributes': attributes or {}})


class ModelTests(unittest.TestCase):
    def test_reject_naive_time(self):
        with self.assertRaises(ValueError):
            Event.parse({**event(1).to_dict(), 'timestamp': '2026-01-01T00:00:00'})

    def test_reject_nested_attributes(self):
        with self.assertRaises(ValueError):
            Event.parse({**event(1).to_dict(), 'attributes': {'nested': {'x': 1}}})

    def test_host_token_salted(self):
        self.assertNotEqual(host_token('a', 'salt1'), host_token('a', 'salt2'))

    def test_reject_empty_salt(self):
        with self.assertRaises(ValueError): host_token('a', '')


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'evidence.sqlite3')
        self.ledger = Ledger(self.path)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def test_chain_and_duplicate(self):
        self.assertTrue(self.ledger.append(event(1)))
        self.assertFalse(self.ledger.append(event(1)))
        self.assertTrue(self.ledger.append(event(2)))
        self.assertTrue(self.ledger.verify()['valid'])
        self.assertEqual(self.ledger.verify()['event_count'], 2)

    def test_detect_modified_payload(self):
        self.ledger.append(event(1))
        self.ledger.db.execute("UPDATE events SET payload='{}' WHERE event_id='e1'")
        self.ledger.db.commit()
        self.assertFalse(self.ledger.verify()['valid'])

    def test_detect_deleted_middle_entry(self):
        for i in range(3): self.ledger.append(event(i))
        self.ledger.db.execute("DELETE FROM events WHERE event_id='e1'")
        self.ledger.db.commit()
        self.assertFalse(self.ledger.verify()['valid'])

    def test_independent_hosts(self):
        self.ledger.append(event(1, host='a'))
        self.ledger.append(event(1, host='b'))
        self.assertTrue(self.ledger.verify()['valid'])
        self.assertEqual(len(self.ledger.verify()['host_heads']), 2)


class DetectionTests(unittest.TestCase):
    def test_office_shell(self):
        results = Correlator().process(event(1, attributes={'name': 'powershell.exe', 'parent_name': 'winword.exe'}))
        self.assertEqual(results[0]['rule_id'], 'SF-PROC-001')

    def test_no_alert_for_normal_process(self):
        self.assertFalse(Correlator().process(event(1, attributes={'name': 'notepad.exe'})))

    def test_authentication_sequence(self):
        engine = Correlator()
        for i in range(5):
            self.assertFalse(engine.process(event(i, 'authentication', {'source_ip': '10.0.0.2', 'account': 'user', 'outcome': 'failure'}, second=i)))
        result = engine.process(event(6, 'authentication', {'source_ip': '10.0.0.2', 'account': 'user', 'outcome': 'success'}, second=6))
        self.assertEqual(result[0]['rule_id'], 'SF-AUTH-001')

    def test_cross_host_isolation(self):
        engine = Correlator()
        for i in range(5):
            engine.process(event(i, 'authentication', {'source_ip': '1.2.3.4', 'outcome': 'failure'}, host='a', second=i))
        self.assertFalse(engine.process(event(8, 'authentication', {'source_ip': '1.2.3.4', 'outcome': 'success'}, host='b', second=8)))

    def test_window_expiration(self):
        engine = Correlator(window_seconds=60)
        for i in range(5):
            engine.process(event(i, 'authentication', {'source_ip': '1.2.3.4', 'outcome': 'failure'}, second=i))
        self.assertFalse(engine.process(event(8, 'authentication', {'source_ip': '1.2.3.4', 'outcome': 'success'}, second=120)))

    def test_file_to_process_correlation(self):
        engine = Correlator()
        engine.process(event(1, 'file', {'path': '/tmp/sample.exe', 'action': 'created'}))
        result = engine.process(event(2, 'process', {'path': '/tmp/sample.exe'}, second=5))
        self.assertEqual(result[0]['rule_id'], 'SF-CORR-002')

    def test_control_tampering(self):
        result = Correlator().process(event(1, 'security_control', {'action': 'disabled'}))
        self.assertEqual(result[0]['rule_id'], 'SF-CTRL-001')

    def test_password_spray(self):
        engine = Correlator()
        result = []
        for i in range(10):
            result = engine.process(event(i, 'authentication', {'source_ip': '1.2.3.4', 'account': f'user{i%5}', 'outcome': 'failure'}, second=i))
        self.assertEqual(result[0]['rule_id'], 'SF-AUTH-002')


class CLITests(unittest.TestCase):
    def test_ingest_and_replay_deduplication(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.jsonl'
            path.write_text(json.dumps(event(1, attributes={'name': 'powershell.exe', 'parent_name': 'winword.exe'}).to_dict()) + '\n')
            db = str(Path(temp) / 'db.sqlite3')
            first = ingest(path, db)
            second = ingest(path, db)
            self.assertEqual(first['accepted'], 1)
            self.assertEqual(first['findings'], 1)
            self.assertEqual(second['accepted'], 0)
            self.assertTrue(second['verification']['valid'])

    def test_malformed_line_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.jsonl'
            path.write_text('{broken json}\n')
            result = ingest(path, str(Path(temp) / 'db.sqlite3'))
            self.assertEqual(len(result['rejected']), 1)


if __name__ == '__main__': unittest.main()
