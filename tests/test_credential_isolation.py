"""SF-04: credentials remain local to SMTP, not inherited by collectors."""
import os
import sys
import types
import unittest
from unittest.mock import patch
from sentinelforge.__main__ import load_gmail_credentials, deliver_configured_email
from sentinelforge.channels import send_email
from sentinelforge.core import Alert
from sentinelforge.windows import fetch


class CredentialIsolationTests(unittest.TestCase):
    def test_keyring_lookup_does_not_modify_environment(self):
        fake = types.SimpleNamespace(get_password=lambda service, sender: 'fixture-secret')
        with patch.dict(sys.modules, {'keyring': fake}), patch.dict(os.environ, {}, clear=True):
            creds = load_gmail_credentials({'mode': 'email', 'gmail_from': 'sender@gmail.com'})
            self.assertEqual(creds, ('sender@gmail.com', 'fixture-secret'))
            self.assertNotIn('SENTINELFORGE_GMAIL_APP_PASSWORD', os.environ)

    def test_missing_keyring_secret_fails_closed(self):
        fake = types.SimpleNamespace(get_password=lambda service, sender: None)
        with patch.dict(sys.modules, {'keyring': fake}):
            self.assertIsNone(load_gmail_credentials({'mode': 'email', 'gmail_from': 'sender@gmail.com'}))

    def test_smtp_uses_explicit_credentials(self):
        alert = Alert('test', 'info', 'Test', '2026-11-17T00:00:00Z', [])
        with patch.dict(os.environ, {}, clear=True), \
             patch('smtplib.SMTP_SSL') as smtp, \
             patch('sentinelforge.channels.ssl.create_default_context') as tls_context:
            send_email(alert, {'mode': 'email', 'email_to': 'recipient@example.invalid'},
                       credentials=('sender@gmail.com', 'fixture-secret'))
            server = smtp.return_value.__enter__.return_value
            server.login.assert_called_once_with('sender@gmail.com', 'fixture-secret')
            self.assertNotIn('SENTINELFORGE_GMAIL_APP_PASSWORD', os.environ)

    def test_collector_child_environment_excludes_secret(self):
        class Result:
            returncode = 0
            stdout = '[]'
            stderr = ''
        with patch.dict(os.environ, {'SENTINELFORGE_GMAIL_APP_PASSWORD': 'secret',
                                     'SENTINELFORGE_GMAIL_FROM': 'sender@gmail.com'}):
            with patch('sentinelforge.windows.subprocess.run', return_value=Result()) as run:
                fetch('Security', 0)
            env = run.call_args.kwargs['env']
            self.assertNotIn('SENTINELFORGE_GMAIL_APP_PASSWORD', env)
            self.assertNotIn('SENTINELFORGE_GMAIL_FROM', env)

    def test_agent_passes_keyring_secret_to_delivery_not_environment(self):
        with patch('sentinelforge.__main__.load_config', return_value={
                'mode': 'email', 'email_to': 'recipient@example.invalid',
                'gmail_from': 'sender@gmail.com'}), \
             patch('sentinelforge.__main__.load_gmail_credentials',
                   return_value=('sender@gmail.com', 'fixture-secret')), \
             patch('sentinelforge.__main__.deliver_channels') as deliver:
            deliver_configured_email(object())
            self.assertEqual(deliver.call_args.kwargs['credentials'],
                             ('sender@gmail.com', 'fixture-secret'))

if __name__ == '__main__':
    unittest.main()
