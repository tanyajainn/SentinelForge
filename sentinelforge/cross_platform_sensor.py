"""Read-only, cross-platform endpoint metadata sensor (Windows/macOS/Linux).

Explicit opt-in; local SQLite only; no payloads, command lines, or remote upload.
Sampling misses short-lived processes and connections. Not antivirus/EDR protection.
"""
from __future__ import annotations
import argparse
import json
import platform
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import psutil

SCHEMA_VERSION = 1

def now():
    return datetime.now(timezone.utc).isoformat()

def connection_key(c):
    if not c.raddr or c.status != 'ESTABLISHED':
        return None
    return (c.pid, c.laddr.ip if c.laddr else None, c.laddr.port if c.laddr else None,
            c.raddr.ip, c.raddr.port)

class Sensor:
    def __init__(self, database: str | Path, process_source=None, connection_source=None):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.database)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS telemetry
            (id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, event_type TEXT NOT NULL,
             payload TEXT NOT NULL)''')
        self.conn.commit()
        self.host_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, platform.node()))
        self.os_name = platform.system().lower()
        self.process_source = process_source or self._processes
        self.connection_source = connection_source or self._connections
        self.process_seen = self._safe_snapshot(self.process_source)
        self.connection_seen = self._safe_snapshot(self.connection_source)
        self.health_errors = []

    @staticmethod
    def _processes():
        seen = set()
        for p in psutil.process_iter(['pid', 'create_time']):
            try:
                if p.info['create_time'] is not None:
                    seen.add((int(p.info['pid']), float(p.info['create_time'])))
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, KeyError, TypeError):
                continue
        return seen

    @staticmethod
    def _connections():
        try:
            connections = psutil.net_connections(kind='tcp')
        except (psutil.AccessDenied, OSError) as exc:
            raise RuntimeError('TCP metadata unavailable; permission or OS restriction') from exc
        return {key for c in connections if (key := connection_key(c)) is not None}

    def _safe_snapshot(self, fn):
        try:
            return fn()
        except (OSError, RuntimeError, psutil.Error):
            return None

    def record(self, event_type, data):
        event = {'schema_version': SCHEMA_VERSION, 'event_type': event_type,
                 'observed_at': now(), 'host_id': self.host_id, 'os': self.os_name,
                 'source': 'psutil_polling', 'data': data}
        with self.conn:
            self.conn.execute('INSERT INTO telemetry(observed_at,event_type,payload) VALUES (?,?,?)',
                              (event['observed_at'], event_type, json.dumps(event, sort_keys=True)))
        return event

    def poll(self):
        events = []
        processes = self._safe_snapshot(self.process_source)
        if processes is None:
            self.health_errors.append('process collection unavailable')
        else:
            if self.process_seen is not None:
                for pid, started in sorted(processes - self.process_seen):
                    events.append(self.record('process_observed', {'pid': pid, 'start_epoch': started}))
            self.process_seen = processes

        connections = self._safe_snapshot(self.connection_source)
        if connections is None:
            self.health_errors.append('TCP collection unavailable')
        else:
            if self.connection_seen is not None:
                for pid, lip, lport, rip, rport in sorted(connections - self.connection_seen, key=str):
                    events.append(self.record('tcp_connection_observed', {
                        'pid': pid, 'local_ip': lip, 'local_port': lport,
                        'remote_ip': rip, 'remote_port': rport}))
            self.connection_seen = connections
        return events

    def close(self):
        self.conn.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', default='evaluation/validation/endpoint_telemetry.sqlite3')
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--duration', type=float, default=60, help='Seconds to collect; 0 runs until Ctrl+C')
    args = parser.parse_args()
    if args.interval < 0.5 or args.duration < 0:
        parser.error('interval must be >= 0.5 seconds and duration >= 0')
    sensor = Sensor(args.database)
    print(f'SentinelForge read-only sensor | OS={sensor.os_name} | local DB={args.database}')
    print('No firewall changes, notifications, or network uploads. Ctrl+C to stop.')
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while deadline is None or time.monotonic() < deadline:
            for event in sensor.poll():
                print(json.dumps(event), flush=True)
            if sensor.health_errors:
                print('COLLECTION WARNING: ' + '; '.join(sorted(set(sensor.health_errors))), flush=True)
                sensor.health_errors.clear()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        sensor.close()

if __name__ == '__main__':
    main()
