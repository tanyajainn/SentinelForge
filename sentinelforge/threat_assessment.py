"""Read-only assessment of SentinelForge failed-logon alerts."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from .attribution import safe_source_ip


def assess(alert):
    """Return a conservative, non-executable response recommendation."""
    if alert.get("rule") != "event-4625-source":
        return {
            "classification": "not_eligible",
            "recommendation": "Review the alert manually.",
            "block_eligible": False,
        }

    evidence = alert.get("evidence") or []
    event = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
    ip = safe_source_ip(event.get("source_ip"))
    logon_type = event.get("logon_type")

    try:
        logon_type = int(logon_type)
    except (TypeError, ValueError):
        logon_type = None

    if not ip:
        return {
            "classification": "unattributed",
            "recommendation": "Investigate locally; no IP blocking recommendation.",
            "block_eligible": False,
        }

    return {
        "classification": "suspicious_failed_logons",
        "source_ip": ip,
        "target_username": event.get("target_username"),
        "logon_type": logon_type,
        "first_failure_at": event.get("first_failure_at"),
        "last_failure_at": alert.get("timestamp"),
        "severity": alert.get("severity"),
        "recommendation": (
            "Investigate the source and verify the activity independently "
            "before considering a manually approved firewall rule."
        ),
        "block_eligible": False,
    }


def recent_assessments(db_path, limit=20):
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute(
            "SELECT payload FROM alerts WHERE rule=? ORDER BY id DESC LIMIT ?",
            ("event-4625-source", limit),
        ).fetchall()

    return [assess(json.loads(row[0])) for row in rows]


def main():
    parser = argparse.ArgumentParser(
        description="Read-only SentinelForge threat assessment"
    )
    parser.add_argument("--db", required=True)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    if not 1 <= args.limit <= 100:
        parser.error("--limit must be between 1 and 100")

    print(json.dumps(recent_assessments(args.db, args.limit), indent=2))


if __name__ == "__main__":
    main()
