"""Export endpoint summaries and combine a reporting period into a campus report."""
import argparse
import json
import re
import sqlite3
from collections import Counter
from contextlib import closing
from datetime import date, datetime, timezone
from html import escape
from pathlib import Path

from .channels import next_steps
from .core import RULES
from .pilot import _table
from .windows import CHANNELS

NAMES = {f"event-{number}": title for number, (_, title) in RULES.items()}
NAMES["other"] = "Other recorded rule"
NAMES["self-test"] = "Delivery self-test"
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}")
STATES = {"read error", "last read succeeded", "no check recorded"}


def snapshot(db_path, endpoint, start, end):
    if not LABEL.fullmatch(endpoint) or start > end:
        raise ValueError("Use a short endpoint alias and chronological UTC dates")
    counts = Counter()
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        for rule, n in db.execute("SELECT rule, COUNT(*) FROM alerts WHERE date(timestamp) "
                                  "BETWEEN ? AND ? GROUP BY rule", (str(start), str(end))):
            key = "self-test" if rule == "sentinelforge-self-test" else rule
            counts[key if key in NAMES else "other"] += n
        checks = dict(db.execute("SELECT channel, error IS NOT NULL FROM channel_health"))
        failed = db.execute("SELECT COUNT(*) FROM alerts a JOIN notification_state n ON n.alert_id=a.id "
                            "WHERE n.channel='email' AND n.status='failed' AND date(a.timestamp) "
                            "BETWEEN ? AND ?", (str(start), str(end))).fetchone()[0]
    health = {channel: ("no check recorded" if channel not in checks else
                        "read error" if checks[channel] else "last read succeeded") for channel in CHANNELS}
    return dict(version=1, endpoint=endpoint, start=str(start), end=str(end),
                generated=datetime.now(timezone.utc).isoformat(), counts=dict(counts),
                health=health, failed_email=failed)


def validate(data):
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("Unsupported summary format")
    if not LABEL.fullmatch(data["endpoint"]):
        raise ValueError("Invalid endpoint alias")
    if date.fromisoformat(data["start"]) > date.fromisoformat(data["end"]):
        raise ValueError("Reversed reporting period")
    if datetime.fromisoformat(data["generated"]).tzinfo is None:
        raise ValueError("Summary timestamp needs a timezone")
    if not isinstance(data["counts"], dict) or any(
        k not in NAMES or type(v) is not int or v < 0 for k, v in data["counts"].items()
    ):
        raise ValueError("Invalid rule counts")
    if set(data["health"]) != set(CHANNELS) or any(v not in STATES for v in data["health"].values()):
        raise ValueError("Invalid channel state")
    if type(data["failed_email"]) is not int or not 0 <= data["failed_email"] <= sum(data["counts"].values()):
        raise ValueError("Invalid failed email count")


def fleet_report(folder):
    endpoints = {}
    period = None
    for file in sorted(folder.glob("*.json")):
        try:
            data = json.loads(file.read_text(encoding="utf-8-sig"))
            validate(data)
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            raise ValueError(f"{file.name}: invalid endpoint summary ({error})") from error
        key = data["endpoint"].casefold()
        if key in endpoints:
            raise ValueError(f"Duplicate endpoint alias in {file.name}")
        dates = data["start"], data["end"]
        if period and dates != period:
            raise ValueError(f"Reporting period differs in {file.name}")
        period = dates
        endpoints[key] = data
    if not endpoints:
        raise ValueError("No endpoint JSON summaries in the input directory")

    totals = Counter()
    detail = []
    for key in sorted(endpoints):
        d = endpoints[key]
        totals.update(d["counts"])
        issues = [f"{c}: {s}" for c, s in d["health"].items() if s != "last read succeeded"]
        detail.append((d["endpoint"], d["generated"], sum(d["counts"].values()) - d["counts"].get("self-test", 0),
                       d["failed_email"], "; ".join(issues) or "Last recorded reads succeeded"))
    actions = [(NAMES[k], n, *next_steps(k)) for k, n in totals.most_common() if k != "self-test"]
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelForge endpoint review</title>
<style>body{{font:16px/1.5 system-ui;color:#183342;margin:4%;max-width:1200px}}td,th{{padding:8px;text-align:left;
vertical-align:top;border-bottom:1px solid #bbb}}table{{border-collapse:collapse}}@media print{{body{{font-size:10pt}}}}</style>
<h1>SentinelForge endpoint review</h1><p>{escape(period[0])} through {escape(period[1])}, UTC.
{len(detail)} reporting endpoints. {totals["self-test"]} self-tests.</p>
<h2>Findings and next steps</h2>{_table(["Finding", "Alerts", "First check", "When to escalate"], actions) if actions else "<p>No rule alerts in the supplied summaries.</p>"}
<h2>Endpoint follow-up</h2>{_table(["Alias", "Snapshot time", "Rule alerts", "Failed email states", "Collection checks"], detail)}
<p>For a read error or missing check, verify the monitor task, log access and last successful read on that endpoint.
For failed emails, check the local outbox and last SMTP error. Confirm receipt separately.</p>
<p>Counts cover submitted snapshots only. Missing endpoints are outside this report. Latest collection states do
not establish continuous coverage. Review the original event locally before classifying an incident.</p></html>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--db", type=Path, default=Path.home() / "SentinelForgeData" / "events.sqlite3")
    snap.add_argument("--endpoint", required=True)
    snap.add_argument("--from-date", type=date.fromisoformat, required=True)
    snap.add_argument("--to-date", type=date.fromisoformat, required=True)
    snap.add_argument("--out", required=True, type=Path)
    report = sub.add_parser("report")
    report.add_argument("--input", required=True, type=Path)
    report.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            result = json.dumps(snapshot(args.db, args.endpoint, args.from_date, args.to_date), indent=2)
        else:
            result = fleet_report(args.input)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as stream:
            stream.write(result)
        print(args.out.resolve())
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"Report failed: {error}\n")


if __name__ == "__main__":
    main()
