"""Read Windows Event Log via built-in PowerShell (no third-party dependencies)."""
from __future__ import annotations
import json
import subprocess
from .core import Event

CHANNELS = {
    'Security': [4625, 4624, 4720, 4728, 4732, 4697, 1102, 4719],
    'System': [7045],
    'Microsoft-Windows-Windows Defender/Operational': [1116, 1117, 1118, 5007],
}

def fetch(channel: str, after_id: int, max_events: int = 500) -> list[Event]:
    if channel not in CHANNELS:
        raise ValueError('Unsupported event channel')
    # Filtering by RecordId must happen *inside* the event-log query.
    # Otherwise -MaxEvents may discard relevant new records before Python sees them.
    # Read oldest first so a cap of max_events never skips an unread event.
    ids = ' or '.join(f'EventID={int(event_id)}' for event_id in CHANNELS[channel])
    xpath = f"*[System[({ids}) and (EventRecordID > {int(after_id)})]]"
    ps = f'''$ErrorActionPreference='Stop'
$events = @(Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' -Oldest -MaxEvents {int(max_events)} -ErrorAction SilentlyContinue)
@($events | ForEach-Object {{ [pscustomobject]@{{channel=$_.LogName;record_id=[long]$_.RecordId;event_id=[int]$_.Id;timestamp=$_.TimeCreated.ToUniversalTime().ToString('o');provider=$_.ProviderName;message=($_.Message | Out-String).Trim()}} }}) | ConvertTo-Json -Depth 4 -Compress
'''
    p = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',ps],
                       capture_output=True, text=True, timeout=90,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if p.returncode != 0:
        raise RuntimeError(f'Unable to read {channel}: {p.stderr.strip()[:400]}')
    raw = p.stdout.strip()
    if not raw or raw == 'null':
        return []
    rows = json.loads(raw)
    if isinstance(rows, dict):
        rows = [rows]
    return [Event(**r) for r in rows]

