"""Opt-in SQLite-backed advisory correlation for Security 4625.

Research preview: never triggers automatic remediation or firewall actions.
The caller runs observe() inside Store.ingest_batch's SQLite transaction.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from .attribution import safe_source_ip
from .core import Alert

MAX_FAILURE_ROWS = 5000
MAX_EMISSION_ROWS = 1000
FAST_WINDOW_MINUTES = 4
MIN_DIVERSITY = 5


def setup(db):
    """Create separate opt-in tables; existing detector schema is untouched."""
    db.execute('''CREATE TABLE IF NOT EXISTS v3_failure_evidence (
        channel TEXT NOT NULL, record_id INTEGER NOT NULL,
        instant_us INTEGER NOT NULL, account_key TEXT NOT NULL,
        source_ip TEXT NOT NULL, PRIMARY KEY(channel, record_id))''')
    db.execute('CREATE INDEX IF NOT EXISTS v3_pair_idx ON v3_failure_evidence(channel,source_ip,account_key,instant_us)')
    db.execute('CREATE INDEX IF NOT EXISTS v3_account_idx ON v3_failure_evidence(channel,account_key,instant_us)')
    db.execute('''CREATE TABLE IF NOT EXISTS v3_emissions (
        channel TEXT NOT NULL, rule TEXT NOT NULL, entity TEXT NOT NULL,
        emitted_us INTEGER NOT NULL, last_record_id INTEGER NOT NULL,
        PRIMARY KEY(channel, rule, entity))''')
    db.execute('''CREATE TABLE IF NOT EXISTS v3_clock (
        channel TEXT PRIMARY KEY, latest_us INTEGER NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS v3_source_quality (
        channel TEXT NOT NULL, status TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(channel, status))''')


def _account(event):
    username = (event.target_username or '').strip()
    domain = (event.target_domain or '').strip()
    if not username or username == '-' or len(username) > 128 or len(domain) > 128:
        return None
    if any(ord(ch) < 32 for ch in username + domain):
        return None
    return ((domain + '\\' + username) if domain else username).casefold()


def _quality(db, status, channel):
    db.execute('''INSERT INTO v3_source_quality(channel,status,count) VALUES(?,?,1)
        ON CONFLICT(channel,status) DO UPDATE SET count=count+1''', (channel, status))


def _trim(db, channel, now, retention):
    db.execute('DELETE FROM v3_failure_evidence WHERE channel=? AND instant_us<?',
               (channel, now - retention))
    # These two caps are hard, not best-effort; use ROWID order for SQLite compatibility.
    db.execute('''DELETE FROM v3_failure_evidence WHERE rowid IN (
        SELECT rowid FROM v3_failure_evidence
        ORDER BY instant_us DESC, record_id DESC LIMIT -1 OFFSET ?)''',
        (MAX_FAILURE_ROWS,))
    db.execute('DELETE FROM v3_emissions WHERE channel=? AND emitted_us<?',
               (channel, now - 7 * 24 * 60 * 60 * 1000000))
    db.execute('''DELETE FROM v3_emissions WHERE rowid IN (
        SELECT rowid FROM v3_emissions
        ORDER BY emitted_us DESC, last_record_id DESC LIMIT -1 OFFSET ?)''',
        (MAX_EMISSION_ROWS,))


def _emit(db, event, now, detector, rule, entity, title, severity, matched, attribution):
    cooldown = max(1, int(detector.window.total_seconds() * 1000000))
    previous = db.execute('''SELECT emitted_us FROM v3_emissions
        WHERE channel=? AND rule=? AND entity=?''', (event.channel, rule, entity)).fetchone()
    if previous and now - previous[0] < cooldown:
        return []
    db.execute('''INSERT INTO v3_emissions(channel,rule,entity,emitted_us,last_record_id)
        VALUES(?,?,?,?,?) ON CONFLICT(channel,rule,entity) DO UPDATE SET
        emitted_us=excluded.emitted_us,last_record_id=excluded.last_record_id''',
        (event.channel, rule, entity, now, event.record_id))
    evidence = asdict(event)
    evidence.update(policy='opt_in_contextual_v3', source_attribution=attribution,
                    matched_count=matched, confidence='advisory_only',
                    automatic_blocking_allowed=False,
                    note='Windows 4625 patterns do not establish malicious intent')
    return [Alert(rule, severity, title, event.timestamp, [evidence])]


def observe(db, event, detector):
    """Return <=1 advisory alert. Must run inside caller's ingestion transaction.

    Missing/private/invalid source attribution is counted but not correlated;
    no source is assumed from workstation name. No active network probes.
    """
    if event.channel != 'Security' or event.event_id != 4625:
        return []
    dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = int(dt.timestamp() * 1000000)
    account = _account(event)
    ip = safe_source_ip(event.source_ip)
    status = 'public_ipv4' if ip else ('missing_source' if not event.source_ip or
              event.source_ip in ('-', '::', '0.0.0.0') else 'unverifiable_source')
    _quality(db, status, event.channel)
    row = db.execute('SELECT latest_us FROM v3_clock WHERE channel=?', (event.channel,)).fetchone()
    if row and now < row[0]:
        _quality(db, 'out_of_order_event_time', event.channel)
        return []
    db.execute('''INSERT INTO v3_clock(channel,latest_us) VALUES(?,?)
        ON CONFLICT(channel) DO UPDATE SET latest_us=max(latest_us,excluded.latest_us)''',
        (event.channel, now))
    window = int(detector.window.total_seconds() * 1000000)
    fast = min(window, FAST_WINDOW_MINUTES * 60 * 1000000)
    _trim(db, event.channel, now, max(window, fast))
    if not ip or not account:
        if not account:
            _quality(db, 'missing_identity', event.channel)
        return []
    db.execute('''INSERT OR IGNORE INTO v3_failure_evidence
        (channel,record_id,instant_us,account_key,source_ip)
        VALUES(?,?,?,?,?)''', (event.channel, event.record_id, now, account, ip))
    # Cap after insert so the hard row limit is always respected, including replay.
    _trim(db, event.channel, now, max(window, fast))
    minimum = max(MIN_DIVERSITY, detector.threshold)
    distinct_sources = db.execute('''SELECT COUNT(DISTINCT source_ip)
        FROM v3_failure_evidence WHERE channel=? AND account_key=? AND instant_us BETWEEN ? AND ?''',
        (event.channel, account, now-fast, now)).fetchone()[0]
    if distinct_sources >= minimum:
        return _emit(db, event, now, detector, 'v3-distributed-guessing', account,
                     'Possible distributed failed logons against one account', 'medium',
                     distinct_sources, 'unverified_public_ipv4')
    distinct_accounts = db.execute('''SELECT COUNT(DISTINCT account_key)
        FROM v3_failure_evidence WHERE channel=? AND source_ip=? AND instant_us BETWEEN ? AND ?''',
        (event.channel, ip, now-fast, now)).fetchone()[0]
    if distinct_accounts >= minimum:
        return _emit(db, event, now, detector, 'v3-password-spray', ip,
                     'Possible password spraying across accounts', 'medium',
                     distinct_accounts, 'unverified_public_ipv4')
    pair_count = db.execute('''SELECT COUNT(*) FROM v3_failure_evidence
        WHERE channel=? AND source_ip=? AND account_key=? AND instant_us BETWEEN ? AND ?''',
        (event.channel, ip, account, now-window, now)).fetchone()[0]
    if pair_count >= detector.threshold:
        return _emit(db, event, now, detector, 'v3-account-source-burst', ip + '|' + account,
                     'Repeated failed logons for one account and source', 'low',
                     pair_count, 'unverified_public_ipv4')
    return []
