"""SentinelForge unified read-only research runtime."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from sentinelforge.cross_platform_sensor import Sensor
from sf_research.model import Event, canonical_json
from sf_research.evidence import Ledger
from sf_research.detection import Correlator


def normalize(raw):
    """Translate sensor observations into the research event schema."""
    event_type = raw["event_type"]

    mapping = {
        "process_observed": "process",
        "tcp_connection_observed": "network",
    }

    if event_type not in mapping:
        raise ValueError("Unsupported sensor event")

    os_name = {
        "darwin": "macos",
        "macos": "macos",
    }.get(raw["os"], raw["os"])

    data = dict(raw["data"])

    # Stable event identity supports deduplication on replay.
    identity = hashlib.sha256(
        canonical_json(raw).encode("utf-8")
    ).hexdigest()

    return Event.parse({
        "event_id": identity,
        "timestamp": raw["observed_at"],
        "host_id": raw["host_id"],
        "os": os_name,
        "kind": mapping[event_type],
        "source": raw["source"],
        "attributes": data,
    })


class UnifiedRuntime:
    def __init__(self, sensor, ledger):
        self.sensor = sensor
        self.ledger = ledger
        self.engine = Correlator()
        self.events = 0
        self.findings = 0

    def poll(self):
        results = []

        for raw in self.sensor.poll():
            event = normalize(raw)

            if not self.ledger.append(event):
                continue

            self.events += 1

            for finding in self.engine.process(event):
                if self.ledger.save_finding(finding):
                    self.findings += 1
                    results.append(finding)

        return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument(
        "--sensor-db",
        default="evaluation/validation/runtime_sensor.sqlite3"
    )
    parser.add_argument(
        "--evidence-db",
        default="evaluation/validation/runtime_evidence.sqlite3"
    )

    args = parser.parse_args()

    if args.duration < 0 or args.interval < 0.5:
        parser.error("Invalid duration or interval")

    sensor = Sensor(args.sensor_db)
    ledger = Ledger(args.evidence_db)
    runtime = UnifiedRuntime(sensor, ledger)

    print("SentinelForge Unified Runtime v0.3")
    print("Read-only endpoint monitoring")
    print("Evidence database:", args.evidence_db)
    print("Press Ctrl+C to stop.")

    deadline = (
        time.monotonic() + args.duration
        if args.duration else None
    )

    try:
        while deadline is None or time.monotonic() < deadline:
            for finding in runtime.poll():
                print(json.dumps(finding), flush=True)

            if sensor.health_errors:
                print(
                    "Collection warning:",
                    "; ".join(sorted(set(sensor.health_errors))),
                    flush=True
                )
                sensor.health_errors.clear()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        pass

    finally:
        print("Events recorded:", runtime.events)
        print("Findings recorded:", runtime.findings)
        print("Evidence verification:", ledger.verify()["valid"])
        sensor.close()
        ledger.close()


if __name__ == "__main__":
    main()
