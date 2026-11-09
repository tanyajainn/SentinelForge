import os
import smtplib
import unittest
from unittest.mock import patch

from sentinelforge.core import Alert
from sentinelforge.channels import send_email


class SMTPSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, {
            'SENTINELFORGE_GMAIL_FROM': 'sender@example.invalid',
            'SENTINELFORGE_GMAIL_APP_PASSWORD': 'test-only',
        }))
        self.primary = self.enterContext(patch('smtplib.SMTP_SSL'))
        self.fallback = self.enterContext(patch('smtplib.SMTP'))

    def deliver(self):
        send_email(Alert('test', 'info', 'Test', 'now', []),
                   {'mode': 'email', 'email_to': 'test@example.invalid'})

    def test_disconnect_after_acceptance_does_not_resend(self):
        self.primary.return_value.__exit__.side_effect = smtplib.SMTPServerDisconnected()
        self.deliver()
        self.primary.return_value.__enter__.return_value.send_message.assert_called_once()
        self.fallback.assert_not_called()

    def test_disconnect_during_submission_is_left_to_queue_retry(self):
        server = self.primary.return_value.__enter__.return_value
        server.send_message.side_effect = smtplib.SMTPServerDisconnected()
        with self.assertRaises(smtplib.SMTPServerDisconnected):
            self.deliver()
        self.fallback.assert_not_called()

    def test_connection_failure_still_allows_fallback(self):
        self.primary.side_effect = OSError('Connection refused')
        self.deliver()
        server = self.fallback.return_value.__enter__.return_value
        server.starttls.assert_called_once()
        server.send_message.assert_called_once()
