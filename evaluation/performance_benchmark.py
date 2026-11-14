"""Synthetic SentinelForge throughput and persistence benchmark."""
import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelforge.core import Detector, Event, Store


def make_events(count):
    start = datetime(2026, 11, 14, tzinfo=timezone.utc)
    return [
        Event(
            channel="Security",
            record_id=i + 1,
            event_id=4625,
            timestamp=(start + timedelta(seconds=i)).isoformat(),
            provider="Benchmark",
            message="Synthetic failed sign-in",
            source_ip="8.8.8.8" if i % 10 < 5 else "1.1.1.1",
            target_username="benchmark-user",
            logon_type=3,
        )
        for i in range(count)
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if args.events < 1 or args.batch_size < 1:
        parser.error("Events and batch size must be positive")

    events = make_events(args.events)

    with TemporaryDirectory() as folder:
        db_path = str(Path(folder) / "benchmark.sqlite3")
        store = Store(db_path)
        detector = Detector()

        started = time.perf_counter()
        alert_count = 0

        for offset in range(0, len(events), args.batch_size):
            batch = events[offset:offset + args.batch_size]
            alert_count += len(
                store.ingest_batch("Security", batch, detector)
            )

        elapsed = time.perf_counter() - started
        cursor_before = store.cursor("Security")
        saved_alerts = store.db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        integrity = store.db.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        store.db.close()

        restarted = Store(db_path)
        cursor_after = restarted.cursor("Security")
        persisted_alerts = restarted.db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        # Replay the final batch after restart. The cursor should
        # prevent duplicate processing and duplicate alerts.
        replay = restarted.ingest_batch(
            "Security",
            events[-min(args.batch_size, len(events)):],
            Detector(),
        )

        final_alerts = restarted.db.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        restarted.db.close()

        checks = {
            "cursor_preserved": cursor_before == cursor_after == args.events,
            "alerts_preserved": alert_count == saved_alerts == persisted_alerts,
            "duplicate_replay_prevented": len(replay) == 0 and final_alerts == saved_alerts,
            "database_integrity": integrity == "ok",
        }

        result = {
            "events": args.events,
            "batch_size": args.batch_size,
            "elapsed_seconds": round(elapsed, 4),
            "events_per_second": round(args.events / elapsed, 2),
            "alerts_generated": alert_count,
            "checks": checks,
            "all_checks_passed": all(checks.values()),
            "dataset": "synthetic",
        }

        print(json.dumps(result, indent=2))

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(result, indent=2),
                encoding="utf-8",
            )
            print(f"Saved: {args.output}")

        if not all(checks.values()):
            raise SystemExit("Benchmark integrity check failed")


if __name__ == "__main__":
    main()
