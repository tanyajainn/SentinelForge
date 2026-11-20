"""Offline, escaped, read-only HTML presentation for the campus pilot."""
from collections import Counter
from datetime import datetime, timezone
from html import escape


def _table(headers, rows):
    head = ''.join(f'<th scope="col">{escape(str(h))}</th>' for h in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{escape(str(v))}</td>' for v in row) + '</tr>' for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_dashboard(inventory, alerts):
    """Produce a standalone local HTML dashboard. Inputs never become raw markup."""
    states = Counter(row[1] for row in inventory)
    alert_rows = sorted(alerts, key=lambda row: str(row[0]), reverse=True)[:100]
    severities = Counter(str(row[2]).lower() for row in alert_rows)
    live = states['Reporting']
    attention = len(inventory) - live
    critical = severities['critical']
    high = severities['high']
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    status = 'All endpoints reporting' if attention == 0 and inventory else 'Attention required'
    if not inventory:
        status = 'No configured endpoints'
    cards = [
        ('Registered endpoints', len(inventory), 'Total configured in this view'),
        ('Reporting', live, 'Recent publisher check-in'),
        ('Need attention', attention, 'Overdue, missing or unreadable'),
        ('High / critical', high + critical, 'Among latest 100 shown'),
    ]
    card_html = ''.join(
        '<section class="metric"><p>' + escape(label) + '</p><strong>' + str(value)
        + '</strong><small>' + escape(note) + '</small></section>'
        for label, value, note in cards
    )
    style = '''
:root{color-scheme:dark;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:#090f1b;color:#e4eaf4}
.shell{max-width:1320px;margin:auto;padding:36px 28px 72px}
.eyebrow{color:#84a8ea;text-transform:uppercase;letter-spacing:.17em;font-size:12px;font-weight:700}
header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;flex-wrap:wrap}
h1{font-size:clamp(30px,4vw,46px);letter-spacing:-.04em;margin:4px 0}
p{margin:0;color:#a5b4ca}.meta{text-align:right;font-size:13px}
.pill{display:inline-block;border:1px solid #4a6283;border-radius:100px;padding:5px 12px;color:#c8d9fa;margin-top:10px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:28px 0}
.metric{background:#141f31;border:1px solid #293953;border-radius:16px;padding:20px}
.metric p{font-size:13px}.metric strong{display:block;font-size:36px;font-weight:750;line-height:1.3;margin:8px 0}
.metric small{color:#7d93b2;font-size:12px}
.panel{background:#111b2b;border:1px solid #293953;border-radius:16px;overflow:hidden;margin-top:18px}
.panel-title{padding:20px 22px;border-bottom:1px solid #293953}
h2{font-size:18px;margin:0}.panel-title p{font-size:13px;margin-top:5px}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:650px}
th,td{text-align:left;padding:13px 22px;border-bottom:1px solid #233147;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#91a9cb;background:#162337}
td{font-size:13px;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}
footer{font-size:12px;color:#8497b5;margin-top:22px;max-width:900px}
@media(max-width:850px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.meta{text-align:left}}
@media(max-width:480px){.shell{padding:22px 14px}.metrics{grid-template-columns:1fr 1fr;gap:8px}.metric{padding:13px}.metric strong{font-size:27px}}
@media print{:root{color-scheme:light}body{background:white;color:#111}.panel,.metric{background:white;border-color:#999}p,.metric small,footer{color:#333}th,td{border-color:#ccc;color:#111}th{background:#eee}.shell{padding:0}}
'''
    devices = _table(['Device','Publisher state','Last check-in','Collection health'], inventory)
    recent = _table(['Event time','Device','Severity','Finding','Local ID'], alert_rows)
    if not inventory:
        devices += '<p style="padding:16px">No endpoints were supplied.</p>'
    if not alert_rows:
        recent += '<p style="padding:16px">No alert batches found for the configured devices.</p>'
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="refresh" content="15">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>SentinelForge | Campus Security</title><style>' + style + '</style></head>'
            '<body><main class="shell"><header><div><div class="eyebrow">SentinelForge / Campus pilot</div>'
            '<h1>Security overview</h1><p>Endpoint monitoring and alert visibility</p></div>'
            '<div class="meta"><div>Generated ' + escape(generated) + '</div><div class="pill">'
            + escape(status) + '</div><div>Refreshes every 15 seconds</div></div></header>'
            '<div class="metrics">' + card_html + '</div>'
            '<section class="panel"><div class="panel-title"><h2>Endpoint health</h2>'
            '<p>Publisher status and log collection are shown separately</p></div>' + devices + '</section>'
            '<section class="panel"><div class="panel-title"><h2>Recent findings</h2>'
            '<p>Up to 100 most recent alerts across all configured endpoints</p></div>' + recent + '</section>'
            '<footer>Read-only, offline HTML report. A reporting publisher does not prove that all event '
            'channels are healthy. These are recorded alerts, not confirmed security incidents. '
            'Review evidence on the originating endpoint. No raw logs are transferred by this view.</footer></main></body></html>')
