import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.core import Detector, Event, Store


class PersistentFailureCountTests(unittest.TestCase):

    def test_failure_count_survives_detector_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "test.sqlite3")
            start = datetime(2026, 11, 14, tzinfo=timezone.utc)

            def event(number):
                return Event(
                    channel="Security",
                    record_id=number,
                    event_id=4625,
                    timestamp=(
                        start + timedelta(minutes=number)
                    ).isoformat(),
                    provider="Test",
                    message="Synthetic failed login",
                    source_ip="8.8.8.8",
                    target_username="testuser",
                    logon_type=3,
                )

            store = Store(db_path)

            first_detector = Detector(threshold=5)
            self.assertEqual(
                store.ingest_batch(
                    "Security",
                    [event(i) for i in range(1, 4)],
                    first_detector,
                ),
                [],
            )

            store.db.close()

            restarted_store = Store(db_path)
            restarted_detector = Detector(threshold=5)

            alerts = restarted_store.ingest_batch(
                "Security",
                [event(4), event(5)],
                restarted_detector,
            )

            self.assertEqual(len(alerts), 1)
            self.assertEqual(
                alerts[0].evidence[0]["failure_count"], 5
            )

            row = restarted_store.db.execute(
                "SELECT payload FROM alerts "
                "WHERE rule='event-4625-source'"
            ).fetchone()

            self.assertIsNotNone(row)

            import json
            saved = json.loads(row[0])
            self.assertEqual(
                saved["evidence"][0]["failure_count"], 5
            )

            restarted_store.db.close()


if __name__ == "__main__":
    unittest.main()
