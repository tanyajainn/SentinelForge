"""Auditable, simulation-only containment lifecycle."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .containment import plan_containment


class ContainmentManager:
    def __init__(self, database_path):
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(database_path)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS containment_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                closed_at TEXT
            )
        """)
        self.db.commit()

    def create(self, source_ip, failure_count, logon_type,
               recurrence_windows, approved_by, duration_minutes=15):

        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError("Administrator identity required")

        decision = plan_containment(
            source_ip,
            failure_count,
            logon_type,
            recurrence_windows,
            administrator_approved=True,
            duration_minutes=duration_minutes,
        )

        if not decision.approved:
            raise ValueError(decision.reason)

        from .threat_scoring import score_failed_logons

        score = score_failed_logons(
            source_ip, failure_count, logon_type, recurrence_windows
        ).score

        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=duration_minutes)

        with self.db:
            cursor = self.db.execute("""
                INSERT INTO containment_simulations
                (source_ip, score, status, approved_by, reason,
                 created_at, expires_at, closed_at)
                VALUES (?, ?, 'simulated_active', ?, ?, ?, ?, NULL)
            """, (
                decision.source_ip,
                score,
                approved_by.strip(),
                decision.reason,
                now.isoformat(),
                expiry.isoformat(),
            ))

        return cursor.lastrowid

    def expire(self):
        now = datetime.now(timezone.utc).isoformat()

        with self.db:
            cursor = self.db.execute("""
                UPDATE containment_simulations
                SET status='expired', closed_at=?
                WHERE status='simulated_active' AND expires_at<=?
            """, (now, now))

        return cursor.rowcount

    def rollback(self, simulation_id):
        now = datetime.now(timezone.utc).isoformat()

        with self.db:
            cursor = self.db.execute("""
                UPDATE containment_simulations
                SET status='rolled_back', closed_at=?
                WHERE id=? AND status='simulated_active'
            """, (now, simulation_id))

        return cursor.rowcount == 1

    def history(self):
        self.expire()
        return self.db.execute("""
            SELECT id, source_ip, score, status, approved_by,
                   created_at, expires_at, closed_at
            FROM containment_simulations
            ORDER BY id DESC
        """).fetchall()

    def close(self):
        self.db.close()
