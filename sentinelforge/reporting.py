"""Read-only SentinelForge CSV investigation export."""

import csv
import json
import sqlite3
import os
from tempfile import NamedTemporaryFile
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


def alert_details(payload):
    try:
        details = json.loads(payload)
    except (ValueError, TypeError):
        return {}
    return details if isinstance(details, dict) else {}


def spreadsheet_safe(value):
    if value is None:
        return ""
    value = str(value)
    if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def export_csv(db_path, output_path=None, *, severity=None, email_status=None):
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
    database = db_path.resolve()
    reserved = {database, *(Path(str(database) + suffix) for suffix in ("-wal", "-shm", "-journal"))}
    if output_path.resolve() in reserved or (output_path.exists() and output_path.samefile(database)):
        raise ValueError("CSV destination conflicts with the source database")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Read-only database connection. Never update historical alerts.
    uri = db_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=15)
    connection.execute("PRAGMA query_only=ON")

    count = 0
    temporary = None

    try:
        query = """
            SELECT a.id, a.timestamp, a.severity, a.rule, a.payload,
                   COALESCE(n.status, 'not_recorded'),
                   COALESCE(n.attempts, 0), n.updated_at
            FROM alerts a
            LEFT JOIN notification_state n
                ON n.alert_id = a.id AND n.channel = 'email'
        """
        conditions = []
        parameters = []
        if severity is not None:
            conditions.append("a.severity = ?")
            parameters.append(severity)
        if email_status is not None:
            conditions.append("COALESCE(n.status, 'not_recorded') = ?")
            parameters.append(email_status)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY a.id"

        with NamedTemporaryFile(mode="w", newline="", encoding="utf-8-sig",
                               dir=output_path.parent, delete=False) as f:
            temporary = Path(f.name)
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()

            for (
                alert_id, timestamp, severity, rule, payload,
                email_status, attempts, updated_at
            ) in connection.execute(query, parameters):

                details = alert_details(payload)
                evidence = details.get("evidence")
                if isinstance(evidence, dict):
                    evidence = [evidence]
                if not isinstance(evidence, list) or not evidence:
                    evidence = [{}]

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
        os.replace(temporary, output_path)
    finally:
        connection.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return output_path, count
