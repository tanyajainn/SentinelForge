"""Read Windows Event Log via built-in PowerShell (no third-party dependencies)."""
from __future__ import annotations
import json
import subprocess
from .core import Event


class EventBatch(list):
    """Events and unfiltered Windows log bounds captured in the same poll."""
    def __init__(self, events=(), *, oldest=None, newest=None):
        super().__init__(events)
        self.oldest = oldest
        self.newest = newest


CHANNELS = {
    'Security': [4625, 4624, 4720, 4728, 4732, 4697, 1102, 4719, 4698, 4722, 4726, 4740],
    'System': [7045],
    'Microsoft-Windows-Windows Defender/Operational': [1116, 1117, 1118, 5001, 5007, 5013],
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
# Query unfiltered bounds; filtered event IDs alone cannot detect log resets.
try {{
$first = Get-WinEvent -LogName '{channel}' -Oldest -MaxEvents 1 -ErrorAction Stop
$last = Get-WinEvent -LogName '{channel}' -MaxEvents 1 -ErrorAction Stop
$oldestId = [long]$first.RecordId
$newestId = [long]$last.RecordId
}} catch {{
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') {{
        $oldestId = $null; $newestId = $null
    }} else {{ throw }}
}}
try {{
$events = @(Get-WinEvent -LogName '{channel}' -FilterXPath '{xpath}' -Oldest -MaxEvents {int(max_events)} -ErrorAction Stop)
}} catch {{
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound,*') {{ $events = @() }} else {{
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }}
}}
$records = @($events | ForEach-Object {{
$fields = @{{}}
if ($_.Id -in 4625,1116,1117,1118) {{
    foreach ($node in ([xml]$_.ToXml()).Event.EventData.Data) {{
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }}
}}
[pscustomobject]@{{source_ip=$fields['IpAddress'];target_username=$fields['TargetUserName'];logon_type=$fields['LogonType'];detection_id=$fields['Detection ID'];action_name=$fields['Action Name'];channel=$_.LogName;record_id=[long]$_.RecordId;event_id=[int]$_.Id;timestamp=$_.TimeCreated.ToUniversalTime().ToString('o');provider=$_.ProviderName;message=($_.Message | Out-String).Trim()}} }})
[pscustomobject]@{{oldest=$oldestId;newest=$newestId;events=$records}} | ConvertTo-Json -Depth 5 -Compress
'''
    p = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',ps],
                       capture_output=True, text=True, timeout=90,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if p.returncode != 0:
        raise RuntimeError(f'Unable to read {channel}: {p.stderr.strip()[:400]}')
    raw = p.stdout.strip()
    if not raw or raw == 'null':
        return EventBatch()
    data = json.loads(raw)
    # Keep parsing old-shaped responses for mocked collectors and compatibility.
    if isinstance(data, dict) and 'events' in data:
        oldest, newest = data.get('oldest'), data.get('newest')
        rows = data['events'] or []
    else:
        oldest = newest = None
        rows = [data] if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError('Unexpected Windows event response shape')
    if oldest is not None and (type(oldest) is not int or oldest < 0):
        raise ValueError('Invalid oldest RecordID')
    if newest is not None and (type(newest) is not int or newest < 0):
        raise ValueError('Invalid newest RecordID')
    from .attribution import safe_source_ip, safe_logon_type
    for r in rows:
        if r['event_id'] == 4625:
            r['source_ip'] = safe_source_ip(r.get('source_ip'))
            r['logon_type'] = safe_logon_type(r.get('logon_type'))
            r['target_username'] = (
                str(r['target_username'])[:128]
                if r.get('target_username') else None
            )
    return EventBatch((Event(**r) for r in rows), oldest=oldest, newest=newest)

