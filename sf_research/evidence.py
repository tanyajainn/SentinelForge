"""SQLite event and finding ledger with per-host append-only hash chains.

Tamper-evident against accidental or uncoordinated changes, NOT tamper-proof:
an attacker able to rewrite the database can recompute the chain. Export and
independently sign/checkpoint chain heads for stronger assurances.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
from pathlib import Path
from .model import Event, canonical_json

GENESIS = '0' * 64


class Ledger:
    def __init__(self, path: str):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            payload TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            UNIQUE(host_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_events_host ON events(host_id, sequence);
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            payload TEXT NOT NULL
        );
        ''')
        self.db.commit()

    @staticmethod
    def hash_entry(previous: str, payload: str) -> str:
        return hashlib.sha256((previous + '\n' + payload).encode('utf-8')).hexdigest()

    def append(self, event: Event) -> bool:
        payload = canonical_json(event.to_dict())
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if self.db.execute('SELECT 1 FROM events WHERE host_id=? AND event_id=?',
                               (event.host_id, event.event_id)).fetchone():
                return False
            row = self.db.execute('SELECT entry_hash FROM events WHERE host_id=? ORDER BY sequence DESC LIMIT 1',
                                  (event.host_id,)).fetchone()
            previous = row[0] if row else GENESIS
            digest = self.hash_entry(previous, payload)
            self.db.execute('INSERT INTO events(host_id,event_id,timestamp,payload,previous_hash,entry_hash) VALUES (?,?,?,?,?,?)',
                            (event.host_id, event.event_id, event.timestamp, payload, previous, digest))
        return True

    def save_finding(self, finding: dict) -> bool:
        with self.db:
            result = self.db.execute('INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?)',
                (finding['finding_id'], finding['host_id'], finding['timestamp'],
                 finding['rule_id'], finding['severity'], finding['score'], canonical_json(finding)))
        return result.rowcount > 0

    def verify(self) -> dict:
        hosts = {}
        total = 0
        errors = []
        for host, previous, entry, payload, sequence in self.db.execute(
            'SELECT host_id,previous_hash,entry_hash,payload,sequence FROM events ORDER BY sequence'):
            expected_previous = hosts.get(host, GENESIS)
            if previous != expected_previous:
                errors.append({'sequence': sequence, 'error': 'broken link'})
            if self.hash_entry(previous, payload) != entry:
                errors.append({'sequence': sequence, 'error': 'entry hash mismatch'})
            hosts[host] = entry
            total += 1
        return {'valid': not errors, 'event_count': total, 'host_heads': hosts, 'errors': errors}

    def findings(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute('SELECT payload FROM findings ORDER BY timestamp,finding_id')]

    def close(self):
        self.db.close()
