import tempfile
import unittest
from pathlib import Path

from sentinelforge.unified_runtime import normalize, UnifiedRuntime
from sf_research.evidence import Ledger


class RuntimeTests(unittest.TestCase):

    def sample(self, kind="process_observed"):
        return {
            "schema_version": 1,
            "event_type": kind,
            "observed_at": "2026-11-15T10:00:00+00:00",
            "host_id": "test-host",
            "os": "darwin",
            "source": "psutil_polling",
            "data": {"pid": 123, "start_epoch": 123456.0},
        }

    def test_macos_normalization(self):
        event = normalize(self.sample())
        self.assertEqual(event.os, "macos")
        self.assertEqual(event.kind, "process")

    def test_stable_identity(self):
        first = normalize(self.sample())
        second = normalize(self.sample())
        self.assertEqual(first.event_id, second.event_id)

    def test_network_normalization(self):
        event = normalize(
            self.sample("tcp_connection_observed")
        )
        self.assertEqual(event.kind, "network")

    def test_unknown_event_rejected(self):
        with self.assertRaises(ValueError):
            normalize(self.sample("unknown"))

    def test_runtime_deduplicates(self):
        class FakeSensor:
            health_errors = []

            def poll(self):
                return [RuntimeTests().sample()]

        with tempfile.TemporaryDirectory() as folder:
            ledger = Ledger(str(Path(folder) / "evidence.db"))

            try:
                runtime = UnifiedRuntime(FakeSensor(), ledger)
                runtime.poll()
                runtime.poll()

                self.assertEqual(runtime.events, 1)
                self.assertTrue(ledger.verify()["valid"])
            finally:
                ledger.close()


if __name__ == "__main__":
    unittest.main()
