"""SentinelForge local security dashboard."""

import html
import json
import sqlite3
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

DB = Path.home() / "SentinelForgeData" / "events.sqlite3"
LOG = Path.home() / "SentinelForgeData" / "monitor.log"

def get_data():
    alerts = []
    counts = Counter()
    delivered = 0
    baseline = 0

    if DB.exists():
        con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True, timeout=5)
        try:
            rows = con.execute(
                "SELECT id, timestamp, severity, rule, payload "
                "FROM alerts ORDER BY id DESC LIMIT 100"
            ).fetchall()

            for id_, timestamp, severity, rule, payload in rows:
                try:
                    details = json.loads(payload)
                except (ValueError, TypeError):
                    details = {}

                alerts.append({
                    "id": id_,
                    "timestamp": timestamp,
                    "severity": severity,
                    "rule": rule,
                    "title": details.get("title", rule),
                })

            counts.update(dict(con.execute(
                "SELECT lower(severity), COUNT(*) FROM alerts "
                "GROUP BY lower(severity)"
            ).fetchall()))

            delivered = con.execute(
                "SELECT COUNT(*) FROM notification_state "
                "WHERE channel='email' AND status='sent'"
            ).fetchone()[0]
        finally:
            con.close()

    recent_log = LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-30:] if LOG.exists() else []
    last_scan = next(
        (line for line in reversed(recent_log) if "Scan complete:" in line),
        "No scan recorded"
    )

    return alerts, counts, delivered, last_scan

def render():
    alerts, counts, delivered, last_scan = get_data()
    total = sum(counts.values())

    rows = "".join(
        "<tr>"
        f"<td>#{a['id']}</td>"
        f"<td>{html.escape(str(a['timestamp']))}</td>"
        f"<td><span class='sev {html.escape(str(a['severity']).lower())}'>"
        f"{html.escape(str(a['severity']).upper())}</span></td>"
        f"<td>{html.escape(str(a['title']))}</td>"
        f"<td>{html.escape(str(a['rule']))}</td>"
        "</tr>"
        for a in alerts
    )

    if not rows:
        rows = "<tr><td colspan='5'>No alerts recorded.</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>SentinelForge | Security Dashboard</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #090e19; color: #e8edf7;
font: 15px/1.5 system-ui, sans-serif; }}
header {{ border-bottom: 1px solid #273246; padding: 22px 6%;
display: flex; justify-content: space-between; align-items: center; }}
.brand {{ font-size: 23px; font-weight: 800; letter-spacing: -.7px; }}
.brand span {{ color: #68a8ff; }}
.tag {{ color: #9eabc2; font-size: 12px; }}
main {{ max-width: 1300px; margin: auto; padding: 34px 24px; }}
h1 {{ font-size: 29px; margin: 0 0 5px; }}
.sub {{ color: #9eabc2; margin: 0 0 28px; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(190px,1fr));
gap: 14px; margin-bottom: 25px; }}
.card, .panel {{ background: #121b2c; border: 1px solid #273246;
border-radius: 13px; }}
.card {{ padding: 22px; }}
.card label {{ color: #9eabc2; display: block; font-size: 13px; }}
.card strong {{ font-size: 33px; display: block; margin-top: 7px; }}
.panel {{ padding: 23px; margin-bottom: 20px; overflow-x: auto; }}
h2 {{ margin: 0 0 16px; font-size: 18px; }}
table {{ width: 100%; border-collapse: collapse; text-align: left; }}
th {{ color: #9eabc2; font-size: 12px; text-transform: uppercase; }}
th, td {{ padding: 14px; border-bottom: 1px solid #273246; }}
.sev {{ font-weight: 700; font-size: 12px; }}
.high, .critical {{ color: #ff7789; }}
.medium {{ color: #ffd37a; }}
.low {{ color: #7fcbad; }}
code {{ color: #8dc0ff; overflow-wrap: anywhere; }}
footer {{ text-align: center; color: #74839e; padding: 25px; }}
</style>
</head>
<body>
<header>
<div class="brand">SENTINEL<span>FORGE</span></div>
<div class="tag">LOCAL SECURITY CONSOLE · AUTO REFRESH 30s</div>
</header>
<main>
<h1>Security overview</h1>
<p class="sub">Windows event monitoring · Local database · Gmail notifications</p>
<div class="stats">
<div class="card"><label>Total stored alerts</label><strong>{total}</strong></div>
<div class="card"><label>High severity</label><strong>{counts.get('high',0)}</strong></div>
<div class="card"><label>Medium severity</label><strong>{counts.get('medium',0)}</strong></div>
<div class="card"><label>Emails marked sent</label><strong>{delivered}</strong></div>
</div>
<section class="panel">
<h2>Latest scan</h2>
<code>{html.escape(last_scan)}</code>
</section>
<section class="panel">
<h2>Recent security alerts</h2>
<table>
<thead><tr><th>ID</th><th>Timestamp</th><th>Severity</th>
<th>Detection</th><th>Rule</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</section>
</main>
<footer>SentinelForge · Local-only dashboard · No cloud hosting</footer>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path != "/":
            self.send_error(404)
            return
        try:
            body = render().encode("utf-8")
        except Exception:
            self.send_error(500, "Dashboard data unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    address = ("127.0.0.1", 8765)
    print("SentinelForge Dashboard: http://127.0.0.1:8765", flush=True)
    ThreadingHTTPServer(address, Handler).serve_forever()
