import unittest
from datetime import datetime, timedelta, timezone

from sentinelforge.core import Detector, Event


class FailureCountEvidenceTests(unittest.TestCase):

    def test_exact_count_and_window(self):
        detector = Detector(threshold=5, window_minutes=10)
        start = datetime(2026, 11, 14, tzinfo=timezone.utc)
        alerts = []

        for i in range(5):
            event = Event(
                channel="Security",
                record_id=i + 1,
                event_id=4625,
                timestamp=(start + timedelta(minutes=i)).isoformat(),
                provider="Test",
                message="Synthetic failed login",
                source_ip="8.8.8.8",
                target_username="testuser",
                logon_type=3,
            )
            alerts.extend(detector.process(event))

        self.assertEqual(len(alerts), 1)
        evidence = alerts[0].evidence[0]
        self.assertEqual(evidence["failure_count"], 5)
        self.assertEqual(evidence["window_minutes"], 10)

    def test_sources_are_not_mixed(self):
        detector = Detector(threshold=5)
        start = datetime(2026, 11, 14, tzinfo=timezone.utc)

        for i in range(4):
            event = Event(
                "Security", i + 1, 4625,
                start.isoformat(), "Test", "Synthetic",
                source_ip="8.8.8.8",
            )
            self.assertEqual(detector.process(event), [])

        other = Event(
            "Security", 5, 4625,
            start.isoformat(), "Test", "Synthetic",
            source_ip="1.1.1.1",
        )
        self.assertEqual(detector.process(other), [])


if __name__ == "__main__":
    unittest.main()
