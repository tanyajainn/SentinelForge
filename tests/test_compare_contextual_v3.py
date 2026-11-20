"""Research comparison contract tests: no production DB or OS modifications."""
import unittest
from evaluation import compare_contextual_v3 as comparison
from evaluation import contextual_benchmark as baseline
from evaluation import adversarial_logon_audit as adversarial


class V3ComparisonTests(unittest.TestCase):
    def test_v3_is_invoked_through_real_store(self):
        events = baseline.fixture("targeted_brute_force", 12, 0)
        found, rules = comparison.v3_episode(events, threshold=5, window=10)
        self.assertTrue(found)
        self.assertTrue(rules)
        self.assertTrue(all(name.startswith("v3-") for name in rules))

    def test_missing_ip_never_v3_attributed(self):
        events = adversarial.fixture("missing_ip_benign", 2, 0)
        found, rules = comparison.v3_episode(events, threshold=5, window=10)
        self.assertFalse(found)
        self.assertFalse(rules)

    def test_report_counts_and_scope(self):
        report = comparison.compare(seeds=1, repetitions=1, base_seed=99)
        for name, dataset in report["datasets"].items():
            total = len(dataset["scenarios"])
            self.assertEqual(set(dataset["results"]), set(comparison.POLICIES))
            for result in dataset["results"].values():
                m = result["aggregate"]
                self.assertEqual(sum(m[key] for key in ("tp", "fp", "fn", "tn")), total)
            self.assertIn("opt_in_v3_only", comparison.markdown(report))


if __name__ == "__main__":
    unittest.main()
