"""Generate a printable, aggregate report from a read-only SQLite snapshot."""
import sqlite3
from contextlib import closing
from datetime import date, datetime, timezone
from html import escape
from pathlib import Path

from .windows import CHANNELS


def _table(headers, rows):
    head = "".join(f"<th>{escape(str(x))}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(str(x))}</td>" for x in row)
                   + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _time(value):
    if not value:
        return "No recorded time"
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return "Unknown time zone"
        return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "Invalid time"


def pilot_report(db_path, start: date, end: date):
    if end < start:
        raise ValueError("End date precedes start date")
    path = Path(db_path)
    now = datetime.now(timezone.utc)
    # Use one SQLite snapshot across both queries, including when the agent writes.
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        rows = db.execute("""
            SELECT CASE WHEN a.rule = 'sentinelforge-self-test' THEN 'Self-test'
                        WHEN a.severity IN ('info','low','medium','high','critical')
                        THEN a.severity ELSE 'Other' END,
                   CASE WHEN n.status IN ('sent','failed','grouped') THEN n.status
                        WHEN n.status IS NULL THEN 'Unrecorded' ELSE 'Other' END,
                   COUNT(*)
            FROM alerts a LEFT JOIN notification_state n
              ON n.alert_id = a.id AND n.channel = 'email'
            WHERE date(a.timestamp) BETWEEN ? AND ?
            GROUP BY 1, 2 ORDER BY 1, 2
        """, (start.isoformat(), end.isoformat())).fetchall()
        invalid = db.execute("SELECT COUNT(*) FROM alerts WHERE date(timestamp) IS NULL").fetchone()[0]
        health = {name: (checked, success, error) for name, checked, success, error in
                  db.execute("SELECT channel, checked_at, last_success, error IS NOT NULL FROM channel_health")}
    health_rows = []
    for channel in CHANNELS:
        if channel in health:
            checked, success, error = health[channel]
            state = "Read error" if error else "Last check succeeded"
            health_rows.append((channel, state, _time(checked), _time(success)))
        else:
            health_rows.append((channel, "No recorded check", "—", "—"))

    count = sum(n for severity, _, n in rows if severity != "Self-test")
    tests = sum(n for severity, _, n in rows if severity == "Self-test")
    generated = now.strftime("%Y-%m-%d %H:%M:%S")
    table = _table(["Severity or test", "Latest email state", "Alerts"], rows)
    channels = _table(["Log channel", "Latest state", "Checked UTC", "Last success UTC"], health_rows)
    html = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelForge pilot report</title>
<style>body{{font:16px/1.5 system-ui;max-width:960px;margin:4% auto;padding:0 1rem;color:#142d3b}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.45rem;text-align:left;border-bottom:1px solid #aaa}}
h1,h2{{line-height:1.2}}@media print{{body{{margin:0;font-size:11pt}}}}</style>
<h1>SentinelForge pilot report</h1><p>Alert dates {start} through {end}, inclusive (UTC).
Generated {generated} UTC.</p><h2>Stored alerts</h2>
<p><strong>{count} rule alerts · {tests} self-test alerts</strong></p>{table}
<p>Email state reflects the latest recorded disposition at report generation.
Sent means SMTP submission. Inbox arrival requires recipient confirmation.
Unrecorded includes historical alerts without an email state.</p>
<p>Across the database, {invalid} alerts have an unparseable date and are excluded from date totals.</p>
<h2>Collection health at the latest recorded check</h2>{channels}
<p>Check timestamps show how recent each observation is. Historical uptime, confirmed
incidents, missed events and field accuracy require separate measurements.</p></html>"""
    folder = path.parent / "exports"
    folder.mkdir(exist_ok=True)
    output = folder / f"SentinelForge-Pilot-{now.strftime('%Y%m%dT%H%M%S%fZ')}.html"
    with output.open("x", encoding="utf-8") as stream:
        stream.write(html)
    return output
