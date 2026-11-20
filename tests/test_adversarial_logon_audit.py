"""Test synthetic adversarial audit integrity without enshrining bad detection rates."""
import unittest
from datetime import datetime
from evaluation import adversarial_logon_audit as audit


class AdversarialAuditTests(unittest.TestCase):
    def test_fixtures_are_sorted_and_have_identity(self):
        for name in audit.CASES:
            with self.subTest(name=name):
                events = audit.fixture(name, 30, 2)
                self.assertGreaterEqual(len(events), 8)
                self.assertEqual([e.record_id for e in events], list(range(1, len(events)+1)))
                self.assertEqual([datetime.fromisoformat(e.timestamp) for e in events],
                                 sorted(datetime.fromisoformat(e.timestamp) for e in events))
                self.assertTrue(all(e.event_id == 4625 and e.channel == "Security" for e in events))
                self.assertTrue(all(e.target_username and e.target_domain for e in events))

    def test_attack_and_benign_examples_are_present(self):
        self.assertGreaterEqual(sum(x[0] for x in audit.CASES.values()), 3)
        self.assertGreaterEqual(sum(not x[0] for x in audit.CASES.values()), 4)
        self.assertEqual(len({e.target_username for e in audit.fixture("slow_password_spray", 1, 1)}), 18)
        self.assertEqual({e.source_ip for e in audit.fixture("private_ip_targeted", 1, 1)}, {"10.1.2.3"})
        self.assertEqual({e.source_ip for e in audit.fixture("missing_ip_benign", 1, 1)}, {None})

    def test_report_integrity(self):
        output = audit.evaluate(2, 2, 777, 5, 10)
        audit.verify(output)
        report = audit.markdown_report(output)
        self.assertIn("Not production accuracy", report)
        self.assertIn("slow_password_spray", report)
        self.assertIn("±", report)

    def test_guard_does_not_assert_ideal_scores(self):
        # Presence and accounting are essential; false positives are diagnostic.
        report = audit.evaluate(1, 1, 123, 5, 10)
        self.assertGreaterEqual(report["policies"]["experimental_contextual"]["confusion"]["fp"], 1)
        audit.verify(report)


if __name__ == "__main__":
    unittest.main()
