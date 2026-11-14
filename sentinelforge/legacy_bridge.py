"""Bridge legacy Windows alerts into SentinelForge research evidence.

Read-only legacy database access. Separate destination ledger.
No notification delivery or endpoint response.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from sf_research.model import Event
from sf_research.evidence import Ledger
from sf_research.detection import Correlator


def convert_alert(alert_id, raw):
    evidence = raw.get("evidence") or []
    detail = evidence[0] if evidence and isinstance(evidence[0], dict) else {}

    rule = str(raw.get("rule", ""))
    attributes = {
        "legacy_alert_id": alert_id,
        "legacy_rule": rule,
        "severity": str(raw.get("severity", "")),
        "title": str(raw.get("title", ""))[:512],
    }

    kind = "security_control"

    if rule in {"event-4625", "event-4625-source"}:
        kind = "authentication"
        attributes["outcome"] = "failure"
        attributes["source_ip"] = str(detail.get("source_ip") or "")
        attributes["account"] = str(detail.get("target_username") or "")

    elif rule == "event-5001":
        attributes["action"] = "disabled"

    elif rule == "event-5013":
        attributes["action"] = "tamper_blocked"

    else:
        attributes["action"] = "legacy_alert"

    identity = hashlib.sha256(
        f"legacy-alert:{alert_id}".encode()
    ).hexdigest()

    return Event.parse({
        "event_id": identity,
        "timestamp": raw["timestamp"],
        "host_id": "local-windows-agent",
        "os": "windows",
        "kind": kind,
        "source": "sentinelforge_legacy_alert",
        "attributes": attributes,
    })


def bridge(source, destination):
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()

    if source_path == destination_path:
        raise ValueError("Source and destination must differ")

    if not source_path.is_file():
        raise FileNotFoundError(source_path)

    connection = sqlite3.connect(
        source_path.as_uri() + "?mode=ro",
        uri=True,
        timeout=10,
    )

    ledger = Ledger(str(destination_path))
    engine = Correlator()

    accepted = 0
    findings = 0
    rejected = []

    try:
        rows = connection.execute(
            "SELECT id, payload FROM alerts ORDER BY id"
        )

        for alert_id, payload in rows:
            try:
                raw = json.loads(payload)
                event = convert_alert(alert_id, raw)

                if not ledger.append(event):
                    continue

                accepted += 1

                for finding in engine.process(event):
                    if ledger.save_finding(finding):
                        findings += 1

            except (ValueError, TypeError, KeyError) as exc:
                rejected.append({
                    "alert_id": alert_id,
                    "error": str(exc)[:160],
                })

        return {
            "accepted": accepted,
            "findings": findings,
            "rejected": rejected,
            "integrity": ledger.verify(),
        }

    finally:
        connection.close()
        ledger.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()

    result = bridge(args.source, args.destination)
    print(json.dumps(result, indent=2))

    if not result["integrity"]["valid"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
