import unittest

from sentinelforge.channels import format_alert
from sentinelforge.core import Alert


class ActionableEmailTests(unittest.TestCase):
    def test_source_alert_contains_investigation_details(self):
        alert = Alert(
            "event-4625-source",
            "high",
            "5 failed logons from 8.8.8.8",
            "2026-11-14T10:00:00Z",
            [{
                "channel": "Security",
                "record_id": 42,
                "source_ip": "8.8.8.8",
                "target_username": "testuser",
                "logon_type": 3,
                "first_failure_at": "2026-11-14T09:55:00Z",
            }],
        )

        subject, body = format_alert(alert)

        self.assertIn("HIGH", subject)
        self.assertIn("8.8.8.8", body)
        self.assertIn("testuser", body)
        self.assertIn("record 42", body)
        self.assertIn("No automatic blocking", body)

    def test_unverified_source_is_not_presented_as_verified(self):
        alert = Alert(
            "event-4625-source",
            "high",
            "Suspicious failed logons",
            "2026-11-14T10:00:00Z",
            [{"source_ip": "192.168.1.10"}],
        )

        _, body = format_alert(alert)

        self.assertIn("unverified", body)
        self.assertNotIn("Source IP: 192.168.1.10", body)

    def test_legacy_alert_remains_supported(self):
        alert = Alert(
            "event-4625",
            "high",
            "5 failed logons",
            "2026-11-14T10:00:00Z",
            [],
        )

        subject, body = format_alert(alert)

        self.assertIn("HIGH", subject)
        self.assertIn("What to check", body)


if __name__ == "__main__":
    unittest.main()
