"""Optional HTTPS notification; no SMTP dependency."""
import json
import urllib.request
from dataclasses import asdict
from .core import Alert

def notify_ntfy(alert: Alert, topic_url: str, token: str = ''):
    if not topic_url.startswith('https://'):
        raise ValueError('Notification URL must use HTTPS')
    data = json.dumps(asdict(alert), indent=2).encode()
    headers = {'Content-Type':'application/json', 'Title': f'SentinelForge: {alert.title}'[:200], 'Priority': '5' if alert.severity == 'critical' else '4'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    request = urllib.request.Request(topic_url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status
