import unittest

from sentinelforge.threat_scoring import score_failed_logons


class ThreatScoringTests(unittest.TestCase):

    def test_high_scoring_activity(self):
        result = score_failed_logons(
            "8.8.8.8", 25, 10, 3
        )
        self.assertEqual(result.score, 90)
        self.assertEqual(result.level, "high")
        self.assertEqual(result.confidence, "moderate")
        self.assertFalse(result.automatic_block_allowed)

    def test_medium_scoring_activity(self):
        result = score_failed_logons(
            "1.1.1.1", 10, 3, 1
        )
        self.assertEqual(result.score, 45)
        self.assertEqual(result.level, "medium")

    def test_low_scoring_activity(self):
        result = score_failed_logons(
            "8.8.8.8", 2, 2, 0
        )
        self.assertEqual(result.score, 5)
        self.assertEqual(result.level, "low")

    def test_private_address_rejected(self):
        result = score_failed_logons(
            "192.168.1.5", 100, 10, 5
        )
        self.assertEqual(result.level, "insufficient_evidence")
        self.assertEqual(result.score, 0)
        self.assertFalse(result.automatic_block_allowed)

    def test_missing_evidence(self):
        result = score_failed_logons(
            "8.8.8.8", 10
        )
        self.assertEqual(result.confidence, "low")
        self.assertIn(
            "Windows logon type",
            result.missing_evidence
        )
        self.assertFalse(result.automatic_block_allowed)

    def test_invalid_count(self):
        result = score_failed_logons(
            "8.8.8.8", -1, 10, 3
        )
        self.assertEqual(
            result.level, "insufficient_evidence"
        )

    def test_boolean_is_not_a_count(self):
        result = score_failed_logons(
            "8.8.8.8", True, 10, 3
        )
        self.assertEqual(
            result.level, "insufficient_evidence"
        )


if __name__ == "__main__":
    unittest.main()
