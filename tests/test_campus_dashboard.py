import unittest
from sentinelforge.campus_dashboard import render_dashboard


class DashboardTests(unittest.TestCase):
    def test_summary_and_status(self):
        html = render_dashboard([
            ('LAB-01', 'Reporting', 'now', 'Recent checks OK'),
            ('LAB-02', 'No check-in', '-', 'Unknown'),
        ], [('2026-11-20T10:00:00Z', 'LAB-01', 'high', 'Login failures', 11)])
        self.assertIn('Attention required', html)
        self.assertIn('High / critical', html)
        self.assertIn('LAB-02', html)
        self.assertIn('Login failures', html)

    def test_untrusted_content_is_escaped(self):
        html = render_dashboard([('<img src=x onerror=alert(1)>', 'Reporting', 'now', '<script>x</script>')],
                                [('2026', 'LAB-01', 'critical', '<svg onload=alert(1)>', 1)])
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('<svg onload=', html)
        self.assertNotIn('<script>x</script>', html)
        self.assertIn('&lt;svg', html)

    def test_empty_inventory_and_alerts(self):
        html = render_dashboard([], [])
        self.assertIn('No configured endpoints', html)
        self.assertIn('No alert batches found', html)

    def test_only_latest_hundred(self):
        rows = [(f'2026-11-20T12:{i:03d}', 'LAB-01', 'low', f'Alert {i}', i) for i in range(120)]
        html = render_dashboard([], rows)
        self.assertIn('Alert 119', html)
        self.assertNotIn('Alert 0</td>', html)


if __name__ == '__main__':
    unittest.main()
