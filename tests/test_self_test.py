import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinelforge.core import Store
from sentinelforge.__main__ import run_self_test


class SelfTestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / 'test.sqlite3'))
        self.store.baseline()

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def _run(self, action):
        def sleep(_):
            alert_id = self.store.db.execute('SELECT MAX(id) FROM alerts').fetchone()[0]
            if action == 'sent':
                self.store.channel_result(alert_id, 'email')
            elif action == 'failed':
                self.store.channel_result(alert_id, 'email', 'Mock SMTP outage')
        times = iter([0, 1, 2, 3, 4])
        with patch('sentinelforge.__main__.load_config', return_value={
            'mode': 'email', 'email_to': 'recipient@example.test', 'gmail_from': 'sender@gmail.com'
        }), patch('sentinelforge.__main__.load_gmail_credentials', return_value=True):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                ok = run_self_test(self.store, timeout=3, sleep=sleep,
                                   monotonic=lambda: next(times))
            return ok, out.getvalue(), err.getvalue()

    def test_pass_when_background_agent_marks_sent(self):
        ok, out, _ = self._run('sent')
        self.assertTrue(ok)
        self.assertIn('PASS:', out)
        self.assertEqual(self.store.channel_counts('email'), 0)

    def test_report_failed_smtp(self):
        ok, _, err = self._run('failed')
        self.assertFalse(ok)
        self.assertIn('Mock SMTP outage', err)
        self.assertEqual(self.store.channel_counts('email'), 1)

    def test_timeout_if_agent_does_not_process(self):
        ok, _, err = self._run('none')
        self.assertFalse(ok)
        self.assertIn('not marked sent', err)

    def test_reject_unbaselined_database(self):
        self.store.db.execute("DELETE FROM notification_meta WHERE key='baseline'")
        self.store.db.commit()
        with patch('sentinelforge.__main__.load_config', return_value={'mode':'email'}):
            with self.assertRaisesRegex(RuntimeError, 'baseline'):
                run_self_test(self.store, sleep=lambda _:None)
        self.assertEqual(self.store.counts()[0], 0)


if __name__ == '__main__':
    unittest.main()
