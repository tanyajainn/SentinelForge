"""Tests for the read-only SentinelForge live-evidence audit."""
import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "evaluation" / "live_evidence_audit.py"
spec = importlib.util.spec_from_file_location("live_evidence_audit", MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class LiveEvidenceAuditTests(unittest.TestCase):
    def test_valid_event_matched(self):
        response = SimpleNamespace(returncode=0, stdout=json.dumps({
            "channel": "Security", "event_id": 4625, "record_id": 123}), stderr="")
        with patch.object(audit.subprocess, "run", return_value=response) as run:
            self.assertEqual(audit.verify_event("Security", 123, 4625), "matched")
            self.assertIn("EventRecordID=123", run.call_args.args[0][-1])

    def test_denied_and_absent_event_distinct(self):
        with patch.object(audit.subprocess, "run", return_value=SimpleNamespace(returncode=3, stdout="", stderr="")):
            self.assertEqual(audit.verify_event("Security", 123, 4625), "event_not_found")
        with patch.object(audit.subprocess, "run", return_value=SimpleNamespace(returncode=4, stdout="", stderr="denied")):
            self.assertEqual(audit.verify_event("Security", 123, 4625), "query_error")

    def test_reference_allowlist_rejects_injected_channel(self):
        with self.assertRaises(ValueError):
            audit.verify_event("Security'; exit", 123, 4625)

    def test_read_only_filters_synthetic_and_duplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.sqlite3"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, payload TEXT)")
                db.executemany("INSERT INTO alerts (id,payload) VALUES (?,?)", [
                    (1, json.dumps({"evidence": [{"channel":"Security", "record_id":99, "event_id":4625}]})),
                    (2, json.dumps({"evidence": [{"channel":"Security", "record_id":99, "event_id":4625}]})),
                    (3, json.dumps({"evidence": [{"channel":"SentinelForge Test", "record_id":0, "event_id":0}]})),
                ])
            rows = audit.candidates(path, 10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["record_id"], 99)


if __name__ == "__main__":
    unittest.main()
