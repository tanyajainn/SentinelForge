import unittest

from sentinelforge.authentication_v2 import AuthenticationDetector


class AuthenticationV2Tests(unittest.TestCase):
    def test_short_burst(self):
        detector = AuthenticationDetector()
        findings = []

        for i in range(6):
            result = detector.process({
                "event_id": 4625,
                "timestamp": f"2026-01-01T00:00:{i:02d}+00:00",
                "source_ip": "203.0.113.10",
                "target_username": "alice",
                "logon_type": 10,
            })
            if result:
                findings.append(result)

        self.assertEqual(len(findings), 1)

    def test_quiet_workstation(self):
        detector = AuthenticationDetector()

        for i in range(2):
            result = detector.process({
                "event_id": 4625,
                "timestamp": f"2026-01-01T00:00:{i:02d}+00:00",
                "source_ip": None,
                "target_username": "alice",
            })
            self.assertIsNone(result)

    def test_non_authentication_event(self):
        detector = AuthenticationDetector()
        self.assertIsNone(detector.process({
            "event_id": 4624,
            "timestamp": "2026-01-01T00:00:00+00:00",
        }))


if __name__ == "__main__":
    unittest.main()
