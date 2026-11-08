import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinelforge.__main__ import deliver_channels
from sentinelforge.core import Alert, Store


class EmailRetryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.store = Store(str(root / "alerts.sqlite3"))
        self.addCleanup(self.store.db.close)
        self.store.baseline()
        self.alert_id = self.store.save_alert(Alert("test", "info", "Test", "now", []))
        self.config = {"mode": "email", "email_to": "test@example.invalid"}
        for name, kwargs in [
            ("config_path", {"return_value": root / "config.json"}),
            ("check_config", {}),
        ]:
            mock = patch("sentinelforge.__main__." + name, **kwargs)
            mock.start()
            self.addCleanup(mock.stop)

    def result(self):
        return self.store.db.execute(
            "SELECT status, attempts, last_error FROM notification_state "
            "WHERE alert_id=? AND channel='email'", (self.alert_id,)
        ).fetchone()

    @patch("sentinelforge.__main__.send")
    def test_accepted_email_stays_sent_if_retry_file_write_fails(self, send):
        with patch("os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                deliver_channels(self.store, self.config)
        self.assertEqual(self.result(), ("sent", 1, None))
        deliver_channels(self.store, self.config)
        send.assert_called_once()

    @patch("sentinelforge.__main__.send", side_effect=EOFError())
    def test_empty_error_stays_pending_during_cooldown(self, send):
        deliver_channels(self.store, self.config)
        self.assertEqual(self.result(), ("failed", 1, "EOFError"))
        self.assertEqual(self.store.channel_counts("email"), 1)
        deliver_channels(self.store, self.config)
        send.assert_called_once()

