"""Deterministic contracts for the research benchmark, not production accuracy."""
import unittest

from evaluation import contextual_benchmark as benchmark


class ContextualBenchmarkTests(unittest.TestCase):
    def test_scenario_identity_and_source_differences(self):
        spray = benchmark.fixture("password_spraying", 1, 0)
        distributed = benchmark.fixture("distributed_brute_force", 1, 0)
        nat = benchmark.fixture("shared_nat_benign", 1, 0)
        self.assertGreaterEqual(len({e.target_username for e in spray}), 10)
        self.assertEqual(len({e.source_ip for e in spray}), 1)
        self.assertGreaterEqual(len({e.source_ip for e in distributed}), 10)
        self.assertEqual(len({e.target_username for e in distributed}), 1)
        self.assertEqual(len({e.source_ip for e in nat}), 1)
        self.assertEqual(len({e.target_username for e in nat}), len(nat))

    def test_proposed_policy_expected_patterns(self):
        for threshold in benchmark.THRESHOLDS:
            for window in benchmark.WINDOWS:
                for scenario in ("targeted_brute_force", "password_spraying", "distributed_brute_force"):
                    with self.subTest(scenario=scenario, threshold=threshold, window=window):
                        self.assertTrue(benchmark.predict("experimental_contextual",
                            benchmark.fixture(scenario, 20261120, 0), threshold, window))
                self.assertFalse(benchmark.predict("experimental_contextual",
                    benchmark.fixture("shared_nat_benign", 20261120, 0), threshold, window))

    def test_no_secret_or_network_fixture_dependencies(self):
        events = benchmark.fixture("password_spraying", 5, 1)
        self.assertEqual({e.provider for e in events}, {"SyntheticBenchmark"})
        self.assertEqual({e.event_id for e in events}, {4625})
        self.assertEqual({e.channel for e in events}, {"Security"})

    def test_report_and_ci_guardrails(self):
        report = benchmark.evaluate(2, 2, 99)
        self.assertEqual(len(report["experiments"]), 27)
        benchmark.verify_guardrails(report)
        markdown = benchmark.markdown_report(report)
        self.assertIn("synthetic", markdown.lower())
        self.assertIn("±", markdown)
        self.assertIn("experimental contextual", markdown.lower())


if __name__ == "__main__":
    unittest.main()
