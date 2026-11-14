"""Continuous, read-only legacy alert evidence integration."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinelforge.legacy_bridge import convert_alert
from sf_research.evidence import Ledger
from sf_research.detection import Correlator

LOGGER = logging.getLogger("sentinelforge.bridge")


def synchronize(source, destination, batch_size=250):
    """Copy new legacy alerts without modifying their source database."""
    source = Path(source).resolve()
    destination = Path(destination).resolve()

    if source == destination:
        raise ValueError("Source and destination must differ")
    if not source.is_file():
        raise FileNotFoundError(source)
    if not 1 <= batch_size <= 10000:
        raise ValueError("Invalid batch size")

    legacy = sqlite3.connect(
        source.as_uri() + "?mode=ro",
        uri=True,
        timeout=10,
    )
    ledger = None

    try:
        legacy.execute("PRAGMA query_only=ON")
        legacy.execute("PRAGMA busy_timeout=10000")

        # Validate the source schema before creating a destination.
        legacy.execute(
            "SELECT id, payload FROM alerts LIMIT 0"
        )

        ledger = Ledger(str(destination))
        engine = Correlator()

        accepted = 0
        rejected = 0
        findings = 0

        # Replaying the source is intentional: the ledger deduplicates
        # records, including after interruption or process restart.
        cursor = 0

        while True:
            rows = legacy.execute(
                "SELECT id, payload FROM alerts "
                "WHERE id > ? ORDER BY id LIMIT ?",
                (cursor, batch_size),
            ).fetchall()

            if not rows:
                break

            for alert_id, payload in rows:
                cursor = alert_id

                try:
                    raw = json.loads(payload)
                    event = convert_alert(alert_id, raw)
                except (ValueError, TypeError, KeyError) as exc:
                    rejected += 1
                    LOGGER.warning(
                        "Rejected legacy alert %s: %s",
                        alert_id, str(exc)[:160]
                    )
                    continue

                if not ledger.append(event):
                    continue

                accepted += 1

                for finding in engine.process(event):
                    if ledger.save_finding(finding):
                        findings += 1

        integrity = ledger.verify()

        if not integrity["valid"]:
            raise RuntimeError(
                "Forensic evidence integrity verification failed"
            )

        return {
            "accepted": accepted,
            "rejected": rejected,
            "findings": findings,
            "total_evidence": integrity["event_count"],
            "integrity_valid": True,
        }

    finally:
        legacy.close()
        if ledger is not None:
            ledger.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--interval", type=float, default=15)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--log",
        default="evaluation/validation/bridge_health.log"
    )
    args = parser.parse_args()

    if args.interval < 2:
        parser.error("Interval must be at least 2 seconds")

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )

    running = True

    def stop(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    failures = 0

    while running:
        try:
            result = synchronize(
                args.source, args.destination
            )

            failures = 0

            if result["accepted"] or result["rejected"]:
                LOGGER.info(
                    "Synchronization result: %s",
                    json.dumps(result)
                )

            if args.once:
                print(json.dumps(result, indent=2))
                return 0

        except (OSError, sqlite3.Error, ValueError,
                RuntimeError) as exc:
            failures += 1
            LOGGER.error(
                "Synchronization failure %s: %s",
                failures, str(exc)[:300]
            )

            if args.once:
                raise

        if args.once:
            break

        # Short sleeps permit clean shutdown.
        remaining = args.interval
        while running and remaining > 0:
            delay = min(1, remaining)
            time.sleep(delay)
            remaining -= delay

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
