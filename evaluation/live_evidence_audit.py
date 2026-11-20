"""Read-only spot check: do saved SentinelForge alerts reference actual Windows events?

Usage (Windows only):
  python -m evaluation.live_evidence_audit --sample-size 10

This is NOT a detection accuracy test, and it does not generate Windows events.
Only numeric event metadata are included in the JSON output. No event messages,
usernames, emails, or source IPs are exported.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CHANNELS = {
    "Security": {4625, 4624, 4720, 4728, 4732, 4697, 1102, 4719, 4698, 4722, 4726, 4740},
    "System": {7045},
    "Microsoft-Windows-Windows Defender/Operational": {1116, 1117, 1118, 5001, 5007, 5013},
}
DEFAULT_DB = Path.home() / "SentinelForgeData" / "events.sqlite3"


def candidates(db_path: Path, sample_size: int, lookback: int = 2000) -> list[dict]:
    if not db_path.is_file():
        raise FileNotFoundError(f"Alert database not found: {db_path}")
    uri = db_path.resolve().as_uri() + "?mode=ro"
    result = []
    seen = set()
    with sqlite3.connect(uri, uri=True, timeout=10) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute("SELECT id,payload FROM alerts ORDER BY id DESC LIMIT ?", (lookback,))
        for alert_id, payload in rows:
            try:
                data = json.loads(payload)
            except (TypeError, ValueError):
                continue
            evidence = data.get("evidence", []) if isinstance(data, dict) else []
            if not isinstance(evidence, list):
                continue
            for entry in evidence:
                if not isinstance(entry, dict):
                    continue
                channel = entry.get("channel")
                record_id = entry.get("record_id")
                event_id = entry.get("event_id")
                if (channel not in CHANNELS or type(record_id) is not int or
                        type(event_id) is not int or record_id < 1 or
                        event_id not in CHANNELS[channel]):
                    continue
                key = (channel, record_id, event_id)
                if key in seen:
                    continue
                seen.add(key)
                result.append({"alert_id": alert_id, "channel": channel,
                               "record_id": record_id, "event_id": event_id})
                if len(result) >= sample_size:
                    return result
    return result


def verify_event(channel: str, record_id: int, event_id: int) -> str:
    """Check event metadata with native Get-WinEvent, not message text."""
    if channel not in CHANNELS or event_id not in CHANNELS[channel] or type(record_id) is not int or record_id < 1:
        raise ValueError("Invalid event reference")
    # Channel is fixed by allowlist, record ID is numeric: no user-controlled shell input.
    script = f"""$ErrorActionPreference='Stop'
try {{
  $e=Get-WinEvent -LogName '{channel}' -FilterXPath '*[System[EventRecordID={record_id}]]' -MaxEvents 1 -ErrorAction Stop
  [pscustomobject]@{{ record_id=[long]$e.RecordId; event_id=[int]$e.Id; channel=$e.LogName }} | ConvertTo-Json -Compress
}} catch {{
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') {{ exit 3 }}
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 4
}}
"""
    try:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return "query_error"
    if p.returncode == 3:
        return "event_not_found"
    if p.returncode:
        return "query_error"
    try:
        observed = json.loads(p.stdout.strip())
        if (observed.get("record_id") == record_id and
                observed.get("event_id") == event_id and
                observed.get("channel") == channel):
            return "matched"
        return "metadata_mismatch"
    except (TypeError, ValueError, AttributeError):
        return "query_error"


def audit(db: Path, sample_size: int) -> dict:
    items = candidates(db, sample_size)
    for item in items:
        item["status"] = verify_event(item["channel"], item["record_id"], item["event_id"])
    status_counts = {status: sum(item["status"] == status for item in items)
                     for status in ("matched", "event_not_found", "metadata_mismatch", "query_error")}
    return {
        "purpose": "Local Windows Event Log reference cross-check (not detection accuracy)",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "sample_requested": sample_size,
        "sample_checked": len(items),
        "status_counts": status_counts,
        "results": items,
        "limitations": [
            "Checks only existing saved alerts; misses and false positives cannot be calculated.",
            "A missing event may have been overwritten, cleared or be inaccessible.",
            "A matching event establishes a real source reference, not that activity was malicious.",
            "Tests the current machine only, not a fresh installation or end-to-end email delivery.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--sample-size", type=int, default=10)
    parser.add_argument("--out", type=Path, default=Path("evaluation/results/live_evidence_audit.json"))
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("Live Windows Event Log verification requires Windows")
    if not 1 <= args.sample_size <= 50:
        parser.error("--sample-size must be between 1 and 50")
    try:
        results = audit(args.db, args.sample_size)
    except (FileNotFoundError, sqlite3.Error) as exc:
        parser.exit(2, f"Audit failed: {exc}\n")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sample_checked": results["sample_checked"],
                      "status_counts": results["status_counts"],
                      "report": str(args.out)}, indent=2))
    return 0 if results["sample_checked"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
