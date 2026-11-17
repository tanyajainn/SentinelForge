"""Publish endpoint alerts to an IT-managed share and render a local fleet dashboard."""
import argparse
import json
import os
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .core import RULES
from .fleet import LABEL
from .pilot import _table

MAX_BATCH_BYTES = 256 * 1024
MAX_BATCH_FILES = 50
MAX_ROWS_PER_BATCH = 250


def safe_endpoint(root, alias):
    """Validate aliases and reject endpoint links escaping the configured share.

    Assumes the trusted SMB administrator controls the root directory. An
    untrusted share administrator can still race path checks; see threat model.
    """
    if not isinstance(alias, str) or not LABEL.fullmatch(alias):
        raise ValueError("Invalid endpoint alias")
    if alias.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *
                                 (f"COM{i}" for i in range(1, 10)), *
                                 (f"LPT{i}" for i in range(1, 10))}:
        raise ValueError("Reserved endpoint alias")
    root = Path(root)
    folder = root / alias
    if root.is_symlink() or folder.is_symlink():
        raise ValueError("Linked directories are not trusted")
    if not folder.resolve().is_relative_to(root.resolve()):
        raise ValueError("Endpoint escapes share")
    return folder


def read_bounded_json(path):
    """Read a limited-size JSON file; reject linked and oversized files."""
    if path.is_symlink():
        raise ValueError("Linked input file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BATCH_BYTES + 1)
    if len(raw) > MAX_BATCH_BYTES:
        raise ValueError("Campus input exceeds size limit")
    return json.loads(raw.decode("utf-8"))


def event_sort_key(row):
    """Normalize untrusted timestamps to UTC; reject non-string dates."""
    stamp = row[0]
    if not isinstance(stamp, str):
        raise ValueError("Invalid alert timestamp")
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


DATA = Path.home() / "SentinelForgeData"
DB = DATA / "events.sqlite3"


def atomic(path, text):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     suffix=".tmp", delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            temp.unlink(missing_ok=True)
            raise
    try:
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def publish(db, dest):
    # An endpoint can write only its own provisioned directory.
    with closing(sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)) as con:
        batches = sorted(dest.glob("batch-*.json"))
        last = int(batches[-1].stem.split("-")[1]) if batches else 0
        rows = con.execute("SELECT id,timestamp,severity,rule FROM alerts WHERE id>? "
                           "ORDER BY id LIMIT 250", (last,)).fetchall()
        health = con.execute("SELECT channel,checked_at,error IS NULL FROM channel_health").fetchall()
    if rows:
        atomic(dest / f"batch-{rows[-1][0]:020d}.json", json.dumps(rows))
    atomic(dest / "heartbeat.json", json.dumps({"time": time.time(), "channels": health}))
    return len(rows)


def desktop(db, cursor):
    if os.name != "nt":
        return
    with closing(sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)) as con:
        if not cursor.exists():
            newest = con.execute("SELECT coalesce(max(id),0) FROM alerts").fetchone()[0]
            atomic(cursor, str(newest))
            return
        rows = con.execute("SELECT id,severity,rule FROM alerts WHERE id>? AND severity "
                           "IN ('high','critical') ORDER BY id LIMIT 20",
                           (int(cursor.read_text()),)).fetchall()
    if rows:
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/msg.exe"),
                                 os.environ["USERNAME"], "/time:60",
                                 f"SentinelForge: {len(rows)} high or critical alert(s). "
                                 f"Latest: {rows[-1][2]}. See the local dashboard."], timeout=10)
        if result.returncode == 0:
            atomic(cursor, str(rows[-1][0]))


def render(root, devices):
    """Render safely even if an individual endpoint submits malformed data."""
    inventory, alerts = [], []
    for device in devices:
        try:
            folder = safe_endpoint(root, device)
            beat = read_bounded_json(folder / "heartbeat.json")
            if not isinstance(beat, dict):
                raise ValueError("Invalid heartbeat object")
            seen_at = beat["time"]
            if type(seen_at) not in (int, float):
                raise ValueError("Invalid heartbeat time")
            age = time.time() - seen_at
            state = "Reporting" if -30 <= age <= 90 else "Check-in overdue"
            seen = datetime.fromtimestamp(seen_at, timezone.utc).strftime("%H:%M:%S UTC %Y-%m-%d")
            channels = beat["channels"]
            if not isinstance(channels, list) or len(channels) > 20:
                raise ValueError("Invalid channels")
            issues = []
            for entry in channels:
                if not isinstance(entry, list) or len(entry) != 3:
                    raise ValueError("Invalid channel record")
                channel, stamp, ok = entry
                if not isinstance(channel, str) or len(channel) > 128 or type(ok) is not bool:
                    raise ValueError("Invalid channel fields")
                checked = event_sort_key((stamp,))
                if not ok or not -30 <= time.time() - checked.timestamp() <= 180:
                    issues.append(channel)
            health = ", ".join(issues) or ("Recent checks OK" if channels else "No channel checks")
        except FileNotFoundError:
            state, seen, health = "No check-in", "-", "Unknown"
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            state, seen, health = "Unreadable check-in", "-", "Unknown"
        inventory.append((device, state, seen, health))
        try:
            folder = safe_endpoint(root, device)
            files = sorted(folder.glob("batch-*.json"), reverse=True)[:MAX_BATCH_FILES]
            recent = []
            for file in files:
                if not file.name.startswith("batch-") or not file.stem[6:].isdigit():
                    continue
                rows = read_bounded_json(file)
                if not isinstance(rows, list) or len(rows) > MAX_ROWS_PER_BATCH:
                    raise ValueError("Invalid alert batch")
                for row in reversed(rows):
                    if not isinstance(row, list) or len(row) != 4:
                        raise ValueError("Invalid alert row")
                    event_id, stamp, severity, rule = row
                    if (type(event_id) is not int or event_id < 0 or
                        not isinstance(severity, str) or len(severity) > 32 or
                        not isinstance(rule, str) or len(rule) > 128):
                        raise ValueError("Invalid alert fields")
                    event_sort_key((stamp,))
                    label = RULES.get(int(rule[6:]), ("", rule))[1] if rule.startswith("event-") and rule[6:].isdigit() else rule
                    recent.append((stamp, device, severity, label, event_id))
                if len(recent) >= 100:
                    break
            alerts.extend(recent[:100])
        except (OSError, TypeError, ValueError, AttributeError, KeyError, OverflowError):
            inventory[-1] = (device, state, seen, "Alert history unreadable")
            alerts = [row for row in alerts if row[1] != device]
    try:
        ordered = sorted(alerts, key=event_sort_key, reverse=True)[:100]
    except (ValueError, TypeError, OverflowError):
        ordered = []  # Never let malformed timestamps crash the full dashboard.
    return ('<!doctype html><html lang="en"><meta charset=utf-8>'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
            '<meta http-equiv=refresh content=15>'
            '<title>SentinelForge campus</title><style>body{font:16px system-ui;margin:3%}table{border-collapse:collapse}'
            'td,th{padding:7px;text-align:left;border-bottom:1px solid #ccc}</style><h1>Campus monitoring</h1>'
            + '<p>Generated '+datetime.now(timezone.utc).isoformat(timespec="seconds")+'</p>'
            + _table(["Device","Publisher","Last check-in","Collection health"], inventory)
            + '<h2>Latest 100 alerts</h2>' + _table(["Event time","Device","Severity","Finding","Local ID"], ordered)
            + '</html>')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    agent = sub.add_parser("publish")
    agent.add_argument("folder", type=Path)
    agent.add_argument("--db", type=Path, default=DB)
    agent.add_argument("--desktop", action="store_true")
    view = sub.add_parser("view")
    view.add_argument("share", type=Path)
    view.add_argument("devices", nargs="+")
    view.add_argument("--out", type=Path, default=Path("campus-live.html"))
    args = parser.parse_args()
    if args.command == "view" and any(not LABEL.fullmatch(d) for d in args.devices):
        parser.error("Invalid device alias")
    while True:
        try:
            if args.command == "view":
                atomic(args.out, render(args.share, args.devices))
            else:
                if args.desktop:
                    try:
                        desktop(args.db, args.db.with_suffix(".desktop-cursor"))
                    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as exc:
                        print(f"Desktop notification: {exc}", flush=True)
                if publish(args.db, args.folder) == 250:
                    continue
        except (OSError, ValueError, sqlite3.Error) as exc:
            print(exc, flush=True)
        time.sleep(15)


if __name__ == "__main__":
    main()
