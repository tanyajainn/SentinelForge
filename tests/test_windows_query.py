import unittest
from unittest.mock import patch
from sentinelforge.windows import fetch

class TestWindowsQuery(unittest.TestCase):
    def test_filter_before_limit_and_oldest_first(self):
        class R:
            returncode=0
            stdout='[]'
            stderr=''
        with patch('sentinelforge.windows.subprocess.run', return_value=R()) as run:
            self.assertEqual(fetch('Security', 123, 500), [])
        command=run.call_args.args[0][-1]
        self.assertIn('EventRecordID > 123', command)
        self.assertIn('-Oldest', command)
        self.assertIn('-MaxEvents 500', command)
        self.assertNotIn('Where-Object { $_.RecordId -gt', command)

if __name__ == '__main__':
    unittest.main()
