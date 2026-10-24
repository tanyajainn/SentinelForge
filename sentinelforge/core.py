"""Rule-based, local Windows security event detector."""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from pathlib import Path

RULES = {
    1116: ('high', 'Microsoft Defender malware detection'),
    1117: ('medium', 'Microsoft Defender remediation'),
    1118: ('high', 'Microsoft Defender remediation failed'),
    5007: ('medium', 'Microsoft Defender configuration changed'),
    4720: ('high', 'Windows user account created'),
    4728: ('high', 'Member added to security-enabled global group'),
    4732: ('high', 'Member added to security-enabled local group'),
    4697: ('high', 'Service installed (security audit)'),
    7045: ('medium', 'Service installed (System log)'),
    1102: ('critical', 'Security audit log cleared'),
    4719: ('high', 'System audit policy changed'),
    4625: ('low', 'Failed Windows logon'),
    4624: ('info', 'Successful Windows logon'),
}

@dataclass
class Event:
    channel: str
    record_id: int
    event_id: int
    timestamp: str
    provider: str
    message: str

@dataclass
class Alert:
    rule: str
    severity: str
    title: str
    timestamp: str
    evidence: list[dict]

class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS cursor (channel TEXT PRIMARY KEY, record_id INTEGER NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, timestamp TEXT, severity TEXT, rule TEXT, payload TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS delivery (alert_id INTEGER PRIMARY KEY, sent_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, FOREIGN KEY(alert_id) REFERENCES alerts(id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS notification_state (alert_id INTEGER NOT NULL, channel TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT, PRIMARY KEY(alert_id, channel))')
        self.db.execute('CREATE TABLE IF NOT EXISTS notification_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        self.db.commit()

    def is_baselined(self):
        return self.db.execute("SELECT 1 FROM notification_meta WHERE key='baseline'").fetchone() is not None

    def baseline(self):
        if self.is_baselined():
            raise RuntimeError('Historical notification baseline already exists; refusing to reset it')
        # Preserve evidence; mark all existing alerts as historical, never send them.
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO notification_meta(key,value) VALUES('baseline', (SELECT COALESCE(MAX(id),0) FROM alerts))")
        return int(self.db.execute("SELECT value FROM notification_meta WHERE key='baseline'").fetchone()[0])

    def channel_pending(self, channel, limit=25):
        row = self.db.execute("SELECT value FROM notification_meta WHERE key='baseline'").fetchone()
        if row is None:
            raise RuntimeError('Run baseline-notifications before sending alerts')
        baseline_id = int(row[0])
        return [(i, Alert(**json.loads(payload))) for i,payload in self.db.execute("SELECT a.id,a.payload FROM alerts a LEFT JOIN notification_state n ON n.alert_id=a.id AND n.channel=? WHERE a.id>? AND (n.status IS NULL OR n.status='failed') ORDER BY a.id LIMIT ?",(channel,baseline_id,limit))]

    def channel_result(self, alert_id, channel, error=None):
        with self.db:
            self.db.execute("INSERT INTO notification_state(alert_id,channel,status,attempts,last_error,updated_at) VALUES(?,?,?,1,?,?) ON CONFLICT(alert_id,channel) DO UPDATE SET status=excluded.status,attempts=notification_state.attempts+1,last_error=excluded.last_error,updated_at=excluded.updated_at", (alert_id,channel,'failed' if error else 'sent',error,datetime.now(timezone.utc).isoformat()))

    def channel_counts(self, channel):
        row = self.db.execute("SELECT value FROM notification_meta WHERE key='baseline'").fetchone()
        if row is None: return None
        baseline_id=int(row[0])
        return self.db.execute("SELECT COUNT(*) FROM alerts a LEFT JOIN notification_state n ON n.alert_id=a.id AND n.channel=? WHERE a.id>? AND (n.status IS NULL OR n.status='failed')",(channel,baseline_id)).fetchone()[0]

    def cursor(self, channel: str) -> int:
        row = self.db.execute('SELECT record_id FROM cursor WHERE channel=?', (channel,)).fetchone()
        return row[0] if row else 0

    def advance(self, channel: str, record_id: int):
        self.db.execute('INSERT INTO cursor(channel,record_id) VALUES(?,?) ON CONFLICT(channel) DO UPDATE SET record_id=max(record_id,excluded.record_id)', (channel, record_id))
        self.db.commit()

    def save_alert(self, alert: Alert):
        cur = self.db.execute('INSERT INTO alerts(timestamp,severity,rule,payload) VALUES(?,?,?,?)', (alert.timestamp,alert.severity,alert.rule,json.dumps(asdict(alert))))
        self.db.commit()
        return cur.lastrowid

    def pending(self, limit=25):
        return [(i, Alert(**json.loads(payload))) for i, payload in self.db.execute(
            'SELECT a.id,a.payload FROM alerts a LEFT JOIN delivery d ON d.alert_id=a.id WHERE d.sent_at IS NULL ORDER BY a.id LIMIT ?', (limit,))]

    def delivery_result(self, alert_id, error=None):
        self.db.execute('INSERT INTO delivery(alert_id,sent_at,attempts,last_error) VALUES(?,?,1,?) '
                        'ON CONFLICT(alert_id) DO UPDATE SET sent_at=excluded.sent_at, attempts=delivery.attempts+1,last_error=excluded.last_error',
                        (alert_id, datetime.now(timezone.utc).isoformat() if error is None else None, error))
        self.db.commit()

    def counts(self):
        alerts = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        pending = self.db.execute('SELECT COUNT(*) FROM alerts a LEFT JOIN delivery d ON d.alert_id=a.id WHERE d.sent_at IS NULL').fetchone()[0]
        return alerts, pending

class Detector:
    def __init__(self, threshold: int = 5, window_minutes: int = 10):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.failures = defaultdict(deque)
        self.last_burst = {}

    def process(self, event: Event) -> list[Alert]:
        if event.event_id not in RULES:
            return []
        severity, title = RULES[event.event_id]
        now = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        evidence = [asdict(event)]
        # Common Defender UI toggles and internal hash changes are noisy and not
        # evidence of compromise. Preserve raw events in Windows logs.
        if event.event_id == 5007 and any(x in event.message for x in
                ('ToastOrSsoTrigger', 'WdConfigHash')):
            return []
        if event.event_id == 4624:
            return []  # high-volume successful logons need enrichment before alerting
        if event.event_id == 4625:
            # Local aggregate; usernames/IPs should be extracted from event XML in future releases.
            q = self.failures[event.channel]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) < self.threshold:
                return []
            last = self.last_burst.get(event.channel)
            if last and now - last < self.window:
                return []
            self.last_burst[event.channel] = now
            severity, title = 'high', f'{len(q)} failed logons in {int(self.window.total_seconds()/60)} minutes'
        return [Alert(f'event-{event.event_id}', severity, title, event.timestamp, evidence)]
