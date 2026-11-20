"""Read-only evaluation regression tests."""
import unittest
from evaluation.release_audit import evaluate_one, summarize, render

class ReleaseAuditTests(unittest.TestCase):
    def test_one_seed_counts_all_scenarios(self):
        run = evaluate_one(20261111, 2)
        self.assertEqual(len(run['episodes']), 12)
        self.assertIn(run['chosen_threshold'], (3, 5, 8))
        m = run['metrics']
        self.assertEqual(sum(m[k] for k in ('tp','fp','fn','tn')), 12)

    def test_aggregation_keeps_false_positive_categories(self):
        a = evaluate_one(20261111, 2)
        b = evaluate_one(20261113, 2)
        s = summarize([a,b])
        self.assertEqual(s['runs'], 2)
        self.assertEqual(sum(v['episodes'] for v in s['scenario_breakdown'].values()), 24)
        self.assertEqual(sum(v['false_positives'] for v in s['scenario_breakdown'].values()), s['aggregate']['fp'])

    def test_html_contains_clear_limits(self):
        s = summarize([evaluate_one(20261111, 1)])
        html = render({'generated_utc':'2026-11-20T00:00:00Z','summary':s})
        self.assertIn('Do not interpret as production accuracy', html)
        self.assertIn('stale service credential', html)

    def test_no_mutation_of_benchmark_threshold(self):
        run = evaluate_one(20261111, 2)
        self.assertEqual(run['chosen_threshold'], max((3,5,8), key=lambda t: (
            run['calibration'][t]['f1'], -run['calibration'][t]['fp'], t)))

if __name__ == '__main__':
    unittest.main()
