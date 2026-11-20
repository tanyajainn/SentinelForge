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
from .campus_dashboard import render_dashboard

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
    inventory, alerts = [], []
    for device in devices:
        folder = root / device
        try:
            beat = json.loads((folder / "heartbeat.json").read_text(encoding="utf-8"))
            age = time.time() - beat["time"]
            state = "Reporting" if -30 <= age <= 90 else "Check-in overdue"
            seen = datetime.fromtimestamp(beat["time"], timezone.utc).strftime("%H:%M:%S UTC %Y-%m-%d")
            issues = [channel for channel, stamp, ok in beat["channels"]
                      if not ok or time.time()-datetime.fromisoformat(stamp).timestamp()>180]
            health = ", ".join(issues) or ("Recent checks OK" if beat["channels"] else "No channel checks")
        except FileNotFoundError:
            state, seen, health = "No check-in", "-", "Unknown"
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            state, seen, health = "Unreadable check-in", "-", "Unknown"
        inventory.append((device, state, seen, health))
        try:
            files = sorted(folder.glob("batch-*.json"), reverse=True)
            recent = []
            for file in files:
                rows = json.loads(file.read_text(encoding="utf-8"))
                for event_id, stamp, severity, rule in reversed(rows):
                    label = RULES.get(int(rule[6:]), ("", rule))[1] if rule.startswith("event-") and rule[6:].isdigit() else rule
                    recent.append((stamp, device, severity, label, event_id))
                if len(recent) >= 100:
                    break
            alerts.extend(recent[:100])
        except (OSError, TypeError, ValueError, AttributeError):
            inventory[-1] = (device, state, seen, "Alert history unreadable")
    return render_dashboard(inventory, alerts)


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
