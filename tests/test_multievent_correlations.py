"""Synthetic multi-event security correlation regression tests."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sentinelforge.core import Detector, Event, Store
from sentinelforge.windows import fetch

START = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def event(record, eid, seconds=None, **fields):
    return Event(
        channel="Security", record_id=record, event_id=eid,
        timestamp=(START + timedelta(seconds=(record * 10 if seconds is None else seconds))).isoformat(),
        provider="SyntheticTest", message="Synthetic test event", **fields,
    )


def correlated(alerts, rule):
    return [item for item in alerts if item.rule == rule]


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.filename = str(Path(self.temp.name) / "alerts.sqlite3")
        self.store = Store(self.filename)
        self.detector = Detector(threshold=3, window_minutes=10)

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def ingest(self, *items):
        return self.store.ingest_batch("Security", items, self.detector)

    def restart(self):
        self.store.db.close()
        self.store = Store(self.filename)
        self.detector = Detector(threshold=3, window_minutes=10)

    @staticmethod
    def failure(record, **fields):
        return event(record, 4625, source_ip="8.8.8.8", target_username="Alice",
                     target_domain="LAB", **fields)

    @staticmethod
    def success(record, **fields):
        return event(record, 4624, source_ip="8.8.8.8", target_username="Alice",
                     target_domain="LAB", **fields)

    def test_failures_then_success_same_account_source(self):
        self.assertEqual(correlated(self.ingest(self.failure(1), self.failure(2), self.failure(3)),
                                    "correlation-logon-success"), [])
        found = correlated(self.ingest(self.success(4)), "correlation-logon-success")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].evidence[0]["matched_failure_count"], 3)

    def test_other_account_source_domain_do_not_match(self):
        self.ingest(self.failure(1), self.failure(2), self.failure(3))
        candidates = [
            event(4, 4624, source_ip="8.8.8.8", target_username="Bob", target_domain="LAB"),
            event(5, 4624, source_ip="1.1.1.1", target_username="Alice", target_domain="LAB"),
            event(6, 4624, source_ip="8.8.8.8", target_username="Alice", target_domain="OTHER"),
        ]
        self.assertEqual(correlated(self.ingest(*candidates), "correlation-logon-success"), [])

    def test_no_account_or_public_ip_no_correlation(self):
        self.ingest(*[event(i, 4625, target_username="Alice") for i in (1, 2, 3)])
        self.assertEqual(correlated(self.ingest(event(4, 4624, target_username="Alice")),
                                    "correlation-logon-success"), [])
        self.ingest(*[event(i, 4625, source_ip="10.10.0.9", target_username="Bob")
                      for i in (5, 6, 7)])
        self.assertEqual(correlated(self.ingest(event(8, 4624, source_ip="10.10.0.9",
                                                       target_username="Bob")),
                                    "correlation-logon-success"), [])

    def test_restart_and_repeated_ingest_idempotent(self):
        self.ingest(self.failure(1), self.failure(2))
        self.restart()
        alerts = self.ingest(self.failure(3), self.success(4))
        self.assertEqual(len(correlated(alerts, "correlation-logon-success")), 1)
        self.assertEqual(self.ingest(self.success(4)), [])
        count = self.store.db.execute(
            "SELECT count(*) FROM alerts WHERE rule='correlation-logon-success'"
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_success_cannot_reuse_old_failures(self):
        self.ingest(self.failure(1), self.failure(2), self.failure(3))
        self.assertEqual(len(correlated(self.ingest(self.success(4)),
                                        "correlation-logon-success")), 1)
        self.assertEqual(correlated(self.ingest(self.success(5), self.failure(6),
                                                self.success(7)),
                                    "correlation-logon-success"), [])
        self.assertEqual(len(correlated(self.ingest(self.failure(8), self.failure(9),
                                                    self.success(10)),
                                        "correlation-logon-success")), 1)

    def test_workstation_fallback_survives_restart_and_isolates_identity(self):
        def log(record, eid, station, user="Alice"):
            return event(record, eid, workstation_name=station, target_username=user)
        self.ingest(*[log(i, 4625, "Desk-A") for i in (1, 2, 3)])
        self.restart()
        self.assertFalse(self.ingest(log(4, 4624, "Desk-B"), log(5, 4624, "Desk-A", "Bob")))
        hit = correlated(self.ingest(log(6, 4624, "DESK-A")), "correlation-logon-success")
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].evidence[0]["correlation_source_kind"], "workstation")
        self.assertIsNone(hit[0].evidence[0]["source_ip"])
        self.assertFalse(self.ingest(log(7, 4624, "Desk-A")))

    def test_expired_failures_do_not_correlate(self):
        self.ingest(*[event(i, 4625, source_ip="8.8.8.8", target_username="Alice",
                            target_domain="LAB", seconds=i * 10) for i in (1, 2, 3)])
        alerts = self.ingest(event(4, 4624, source_ip="8.8.8.8",
                                   target_username="Alice", target_domain="LAB", seconds=3600))
        self.assertEqual(correlated(alerts, "correlation-logon-success"), [])

    def test_new_account_added_to_local_admins(self):
        self.ingest(event(1, 4720, target_username="NewUser",
                          target_sid="S-1-5-21-1-2-3-1111"))
        alerts = self.ingest(event(2, 4732, member_sid="S-1-5-21-1-2-3-1111",
                                   target_sid="S-1-5-32-544"))
        found = correlated(alerts, "correlation-new-privileged-account")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].evidence[0]["created_record_id"], 1)

    def test_unprivileged_or_different_member_not_correlated(self):
        self.ingest(event(1, 4720, target_sid="S-1-5-21-1-2-3-1111"))
        alerts = self.ingest(
            event(2, 4732, member_sid="S-1-5-21-1-2-3-1111", target_sid="S-1-5-32-545"),
            event(3, 4732, member_sid="S-1-5-21-1-2-3-2222", target_sid="S-1-5-32-544"))
        self.assertEqual(correlated(alerts, "correlation-new-privileged-account"), [])

    def test_privileged_group_correlation_survives_restart(self):
        self.ingest(event(1, 4720, target_sid="S-1-5-21-1-2-3-1111"))
        self.restart()
        alerts = self.ingest(event(2, 4728, member_sid="S-1-5-21-1-2-3-1111",
                                   target_sid="S-1-5-21-7-8-9-512"))
        self.assertEqual(len(correlated(alerts, "correlation-new-privileged-account")), 1)

    def test_unrelated_windows_event_behavior_unchanged(self):
        alerts = self.ingest(event(1, 1102))
        self.assertEqual([a.rule for a in alerts], ["event-1102"])


class WindowsEnrichmentTests(unittest.TestCase):
    def test_xml_fields_are_in_powershell_query(self):
        response = SimpleNamespace(returncode=0, stdout="[]", stderr="")
        with patch("sentinelforge.windows.subprocess.run", return_value=response) as call:
            self.assertEqual(fetch("Security", 0), [])
        ps = call.call_args.args[0][-1]
        self.assertIn("4624,4625,4720,4728,4732", ps)
        self.assertIn("WorkstationName", ps)
        self.assertIn("MemberSid", ps)
        self.assertIn("TargetSid", ps)

    def test_enriched_events_parse_without_windows(self):
        rows = [
            dict(channel="Security", record_id=1, event_id=4624,
                 timestamp=START.isoformat(), provider="Test", message="",
                 detection_id=None, action_name=None,
                 source_ip="8.8.8.8", target_username="Alice", logon_type="3",
                 target_domain="LAB", target_sid="S-1-5-21-1-2-3-1000", member_sid=None),
            dict(channel="Security", record_id=2, event_id=4732,
                 timestamp=START.isoformat(), provider="Test", message="",
                 detection_id=None, action_name=None, source_ip=None,
                 target_username="Administrators", logon_type=None,
                 target_domain="Builtin", target_sid="S-1-5-32-544",
                 member_sid="S-1-5-21-1-2-3-1111"),
        ]
        response = SimpleNamespace(returncode=0, stdout=json.dumps(rows), stderr="")
        with patch("sentinelforge.windows.subprocess.run", return_value=response):
            got = fetch("Security", 0)
        self.assertEqual(got[0].source_ip, "8.8.8.8")
        self.assertEqual(got[0].target_domain, "LAB")
        self.assertEqual(got[0].logon_type, 3)
        self.assertEqual(got[1].member_sid, "S-1-5-21-1-2-3-1111")
        self.assertEqual(got[1].target_sid, "S-1-5-32-544")


if __name__ == "__main__":
    unittest.main()
