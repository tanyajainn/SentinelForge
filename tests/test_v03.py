import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelforge.core import Store, Alert
from sentinelforge.channels import enabled_channels,check_config

class V03Tests(unittest.TestCase):
    def test_baseline_preserves_history_and_suppresses_old(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(str(Path(d)/'db.sqlite3'))
            a=Alert('rule','high','test','2026-10-24T12:00:00+00:00',[])
            old=s.save_alert(a)
            self.assertIsNone(s.channel_counts('email'))
            self.assertEqual(s.baseline(),old)
            self.assertEqual(s.channel_pending('email'),[])
            new=s.save_alert(a)
            self.assertEqual([i for i,_ in s.channel_pending('email')],[new])
            s.channel_result(new,'email')
            self.assertEqual(s.channel_pending('email'),[])
            s.db.close()
    def test_email_retry(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(str(Path(d) / "db.sqlite3"))
            s.baseline()

            alert_id = s.save_alert(
                Alert("rule", "high", "test", "now", [])
            )

            s.channel_result(
                alert_id, "email", "temporary outage"
            )
            self.assertEqual(
                len(s.channel_pending("email")), 1
            )

            s.channel_result(alert_id, "email")
            self.assertEqual(
                len(s.channel_pending("email")), 0
            )
            s.db.close()

    def test_email_only_configuration(self):
        self.assertEqual(
            enabled_channels({"mode": "email"}),
            ["email"]
        )
        self.assertEqual(
            enabled_channels({"mode": "sms"}),
            []
        )
        self.assertEqual(
            enabled_channels({"mode": "both"}),
            []
        )

        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                check_config({
                    "mode": "email",
                    "email_to": "a@b.com"
                })

        with patch.dict("os.environ", {
            "SENTINELFORGE_GMAIL_FROM": "sender@gmail.com",
            "SENTINELFORGE_GMAIL_APP_PASSWORD": "test-password"
        }, clear=True):
            check_config({
                "mode": "email",
                "email_to": "recipient@gmail.com"
            })

            for mode in ("sms", "both"):
                with self.assertRaises(ValueError):
                    check_config({"mode": mode})
