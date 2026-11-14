import unittest
from unittest.mock import patch
from sentinelforge.response import validate_ip, create_rule, rollback, main, PREFIX


class ResponseTests(unittest.TestCase):
    def test_reject_private_loopback_and_reserved(self):
        for ip in ('127.0.0.1', '192.168.1.1', '10.0.0.1', '169.254.1.2', '224.0.0.1', '::1', '1.2.3.4/24'):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                validate_ip(ip)

    def test_public_ip_dry_run(self):
        self.assertEqual(validate_ip('8.8.8.8'), '8.8.8.8')
        with patch('sentinelforge.response.powershell') as ps:
            self.assertEqual(main(['plan', '--ip', '8.8.8.8']), 0)
            ps.assert_not_called()

    def test_approval_required_before_admin_or_firewall(self):
        with patch('sentinelforge.response.require_admin') as admin:
            with self.assertRaises(ValueError):
                create_rule('8.8.8.8', 'case-123', 'yes')
            admin.assert_not_called()

    def test_rollback_rejects_arbitrary_rule(self):
        with self.assertRaises(ValueError):
            rollback('Windows Defender Firewall', 'REMOVE Windows Defender Firewall')

    def test_apply_command_and_audit(self):
        with patch('sentinelforge.response.require_admin'), patch('sentinelforge.response.powershell') as ps, patch('sentinelforge.response.audit') as audit:
            rule = create_rule('8.8.8.8', 'confirmed test case', 'BLOCK 8.8.8.8')
            self.assertTrue(rule.startswith(PREFIX))
            self.assertIn('-Direction Inbound', ps.call_args.args[0])
            audit.assert_called_once()


if __name__ == '__main__':
    unittest.main()
