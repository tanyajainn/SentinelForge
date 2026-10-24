"""Read-only SentinelForge CSV investigation export."""

import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


FIELDS = [
    "alert_id",
    "alert_timestamp",
    "severity",
    "rule",
    "title",
    "source_channel",
    "event_id",
    "record_id",
    "event_timestamp",
    "provider",
    "evidence_message",
    "email_status",
    "email_attempts",
    "email_updated_at",
]


def spreadsheet_safe(value):
    if value is None:
        return ""
    value = str(value)
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def export_csv(db_path, output_path=None):
    db_path = Path(db_path)

    if not db_path.is_file():
        raise FileNotFoundError(f"Alert database missing: {db_path}")

    if output_path is None:
        folder = db_path.parent / "exports"
        folder.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d-%H%M%S-%f"
        )
        output_path = folder / f"SentinelForge-Alerts-{timestamp}.csv"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Read-only database connection. Never update historical alerts.
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=15)
    connection.execute("PRAGMA query_only=ON")

    count = 0

    try:
        query = """
            SELECT a.id, a.timestamp, a.severity, a.rule, a.payload,
                   COALESCE(n.status, 'not_recorded'),
                   COALESCE(n.attempts, 0), n.updated_at
            FROM alerts a
            LEFT JOIN notification_state n
                ON n.alert_id = a.id AND n.channel = 'email'
            ORDER BY a.id
        """

        with output_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()

            for (
                alert_id, timestamp, severity, rule, payload,
                email_status, attempts, updated_at
            ) in connection.execute(query):

                try:
                    details = json.loads(payload)
                except (ValueError, TypeError):
                    details = {}

                evidence = details.get("evidence") or [{}]

                for event in evidence:
                    if not isinstance(event, dict):
                        event = {}

                    row = {
                        "alert_id": alert_id,
                        "alert_timestamp": timestamp,
                        "severity": severity,
                        "rule": rule,
                        "title": details.get("title", ""),
                        "source_channel": event.get("channel", ""),
                        "event_id": event.get("event_id", ""),
                        "record_id": event.get("record_id", ""),
                        "event_timestamp": event.get("timestamp", ""),
                        "provider": event.get("provider", ""),
                        "evidence_message": event.get("message", ""),
                        "email_status": email_status,
                        "email_attempts": attempts,
                        "email_updated_at": updated_at,
                    }

                    writer.writerow({
                        key: spreadsheet_safe(value)
                        for key, value in row.items()
                    })
                    count += 1
    finally:
        connection.close()

    return output_path, count
