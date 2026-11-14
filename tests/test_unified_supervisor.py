import json
import tempfile
import unittest
from pathlib import Path
from sentinelforge.unified_supervisor import commands, write_health

class SupervisorTests(unittest.TestCase):
    def test_commands_are_separate_and_read_only(self):
        result = commands('python', 'source.db', 'evidence.db', 2)
        self.assertEqual(set(result), {'sensor', 'bridge'})
        self.assertIn('sentinelforge.unified_runtime', result['sensor'])
        self.assertIn('sentinelforge.continuous_bridge', result['bridge'])
        self.assertNotIn('firewall', ' '.join(str(result)))

    def test_health_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'health.json'
            write_health(target, {'status': 'running', 'components': {'bridge': 1}})
            self.assertEqual(json.loads(target.read_text())['status'], 'running')

if __name__ == '__main__':
    unittest.main()
