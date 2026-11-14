import unittest

from sentinelforge.threat_assessment import assess


class ThreatAssessmentTests(unittest.TestCase):
    def test_valid_source_requires_manual_review(self):
        alert = {
            "rule": "event-4625-source",
            "severity": "high",
            "timestamp": "2026-11-14T10:00:00Z",
            "evidence": [{
                "source_ip": "8.8.8.8",
                "target_username": "testuser",
                "logon_type": 3,
                "first_failure_at": "2026-11-14T09:55:00Z",
            }],
        }
        result = assess(alert)
        self.assertEqual(result["source_ip"], "8.8.8.8")
        self.assertEqual(result["classification"], "suspicious_failed_logons")
        self.assertFalse(result["block_eligible"])

    def test_invalid_source_is_not_attributed(self):
        alert = {
            "rule": "event-4625-source",
            "evidence": [{"source_ip": "192.168.1.10"}],
        }
        result = assess(alert)
        self.assertEqual(result["classification"], "unattributed")
        self.assertFalse(result["block_eligible"])

    def test_legacy_alert_is_not_eligible(self):
        alert = {
            "rule": "event-4625",
            "evidence": [{"source_ip": "8.8.8.8"}],
        }
        result = assess(alert)
        self.assertEqual(result["classification"], "not_eligible")
        self.assertFalse(result["block_eligible"])


if __name__ == "__main__":
    unittest.main()
