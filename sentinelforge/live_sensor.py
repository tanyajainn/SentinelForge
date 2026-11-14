"""SentinelForge experimental read-only endpoint sensor.

Collects process-start and TCP connection metadata.
Does not read process memory, capture packets, modify
the firewall, terminate processes, or transmit data.
"""

import argparse
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from sentinelforge.unified_analysis import analyze


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def endpoint(address):
    if not address:
        return None
    return {
        "ip": address.ip,
        "port": address.port,
    }


class Sensor:
    def __init__(self, database):
        self.database = Path(database)
        self.database.parent.mkdir(
            parents=True, exist_ok=True
        )

        self.db = sqlite3.connect(str(self.database))

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
        """)

        self.db.commit()

        self.processes = set()
        self.connections = set()

        # Establish initial state without reporting every
        # already-running process as newly launched.
        self.processes = self.snapshot_processes()
        self.connections = self.snapshot_connections()

    def snapshot_processes(self):
        result = set()

        for process in psutil.process_iter(
            ["pid", "create_time"]
        ):
            try:
                info = process.info
                result.add((
                    info["pid"],
                    info["create_time"]
                ))
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        return result

    def snapshot_connections(self):
        result = set()

        try:
            connections = psutil.net_connections(
                kind="tcp"
            )
        except (psutil.AccessDenied, OSError):
            return result

        for connection in connections:
            if connection.status != "ESTABLISHED":
                continue

            if not connection.raddr:
                continue

            result.add((
                connection.pid,
                connection.laddr.ip,
                connection.laddr.port,
                connection.raddr.ip,
                connection.raddr.port
            ))

        return result

    def record(self, event):
        timestamp = utcnow()

        self.db.execute(
            """
            INSERT INTO telemetry
            (timestamp, type, payload)
            VALUES (?, ?, ?)
            """,
            (
                timestamp,
                event["type"],
                json.dumps(event)
            )
        )

        finding = analyze(event)

        if finding:
            self.db.execute(
                """
                INSERT INTO findings
                (timestamp, category, severity,
                 score, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    finding.category,
                    finding.severity,
                    finding.score,
                    json.dumps({
                        "finding": finding.__dict__,
                        "event": event
                    })
                )
            )

            print(
                "[ALERT]",
                finding.category,
                finding.severity,
                finding.reasons,
                flush=True
            )

        self.db.commit()

    def scan_processes(self):
        current = self.snapshot_processes()
        created = current - self.processes

        for pid, created_at in created:
            try:
                process = psutil.Process(pid)

                # Deliberately avoid collecting command lines
                # or environment variables.
                name = process.name()
                parent = process.parent()

                parent_name = (
                    parent.name() if parent else ""
                )

                event = {
                    "type": "process",
                    "pid": pid,
                    "name": name,
                    "parent": parent_name,
                    "created_at": created_at,
                }

                self.record(event)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        self.processes = current

    def scan_connections(self):
        current = self.snapshot_connections()
        created = current - self.connections

        for pid, local_ip, local_port, remote_ip, remote_port in created:
            event = {
                "type": "network_connection",
                "pid": pid,
                "protocol": "TCP",
                "local": {
                    "ip": local_ip,
                    "port": local_port
                },
                "remote": {
                    "ip": remote_ip,
                    "port": remote_port
                }
            }

            self.record(event)

        self.connections = current

    def run(self, interval):
        print(
            "SentinelForge Live Sensor",
            "READ-ONLY MODE",
            flush=True
        )

        print("Database:", self.database)
        print("Press Ctrl+C to stop.")

        try:
            while True:
                self.scan_processes()
                self.scan_connections()
                time.sleep(interval)

        except KeyboardInterrupt:
            print("Sensor stopped.")

        finally:
            self.db.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--database",
        default="evaluation/live_sensor.sqlite3"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=2.0
    )

    args = parser.parse_args()

    if args.interval < 0.5:
        parser.error(
            "Minimum polling interval is 0.5 seconds"
        )

    sensor = Sensor(args.database)
    sensor.run(args.interval)


if __name__ == "__main__":
    main()
