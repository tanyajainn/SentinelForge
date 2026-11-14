"""Deterministic, explainable, bounded-window correlation.

Research rules are hypotheses, not validated malware classifications.
Events should be supplied in timestamp order per host for temporal fidelity.
"""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import timedelta
import hashlib
from .model import Event, utc_time


class Correlator:
    def __init__(self, window_seconds=600):
        if not 30 <= window_seconds <= 86400:
            raise ValueError('window must be 30..86400 seconds')
        self.window = timedelta(seconds=window_seconds)
        self.history = defaultdict(deque)
        self.emitted = set()

    def _finding(self, event, rule, score, reasons, evidence):
        evidence = list(dict.fromkeys(evidence))
        token = '|'.join([event.host_id, rule] + sorted(evidence))
        finding_id = hashlib.sha256(token.encode('utf-8')).hexdigest()[:32]
        if finding_id in self.emitted:
            return None
        self.emitted.add(finding_id)
        return {
            'finding_id': finding_id, 'host_id': event.host_id,
            'timestamp': event.timestamp, 'rule_id': rule,
            'severity': 'critical' if score >= 90 else 'high' if score >= 70 else 'medium',
            'score': score, 'reasons': reasons, 'evidence_event_ids': evidence,
            'recommended_action': 'Investigate and validate; no automatic destructive action.'
        }

    def process(self, event: Event) -> list[dict]:
        key = event.host_id
        now = utc_time(event.timestamp)
        queue = self.history[key]
        # Out-of-order arrivals are accepted but do not retroactively modify earlier decisions.
        while queue and now - queue[0][0] > self.window:
            queue.popleft()
        queue.append((now, event))
        findings = []
        a = event.attributes
        if event.kind == 'security_control' and a.get('action') in {'disabled', 'tamper_blocked'}:
            finding = self._finding(event, 'SF-CTRL-001', 85,
                ['Security control disabled or tamper attempt reported'], [event.event_id])
            if finding: findings.append(finding)
        if event.kind == 'process':
            name = str(a.get('name', '')).lower()
            parent = str(a.get('parent_name', '')).lower()
            if parent in {'winword.exe', 'excel.exe', 'powerpnt.exe'} and name in {'powershell.exe', 'pwsh.exe', 'cmd.exe'}:
                finding = self._finding(event, 'SF-PROC-001', 75,
                    ['Office application launched a command interpreter'], [event.event_id])
                if finding: findings.append(finding)
            # Cross-signal: process executing from a temp directory after a suspicious file event.
            path = str(a.get('path', '')).lower().replace('\\', '/')
            if '/temp/' in path or '/tmp/' in path:
                candidates = [(ts, e) for ts, e in queue if e.kind == 'file' and
                              str(e.attributes.get('path', '')).lower().replace('\\', '/') == path and
                              e.attributes.get('action') in {'created', 'modified'} and ts <= now]
                if candidates:
                    finding = self._finding(event, 'SF-CORR-002', 70,
                        ['Executable launched from a temporary path after file creation/change'],
                        [candidates[-1][1].event_id, event.event_id])
                    if finding: findings.append(finding)
        if event.kind == 'authentication':
            ip = str(a.get('source_ip', ''))
            account = str(a.get('account', ''))
            if ip and a.get('outcome') == 'success':
                failures = [e for ts, e in queue if ts <= now and e.kind == 'authentication' and
                            e.attributes.get('source_ip') == ip and e.attributes.get('outcome') == 'failure']
                if len(failures) >= 5:
                    finding = self._finding(event, 'SF-AUTH-001', 80,
                        ['Successful authentication after >=5 failures from same source within window'],
                        [e.event_id for e in failures[-5:]] + [event.event_id])
                    if finding: findings.append(finding)
            if ip and a.get('outcome') == 'failure':
                failures = [e for ts, e in queue if ts <= now and e.kind == 'authentication' and
                            e.attributes.get('source_ip') == ip and e.attributes.get('outcome') == 'failure']
                distinct = {str(e.attributes.get('account', '')) for e in failures if e.attributes.get('account')}
                if len(failures) >= 10 and len(distinct) >= 5:
                    finding = self._finding(event, 'SF-AUTH-002', 85,
                        ['Repeated authentication failures across >=5 accounts from one source'],
                        [e.event_id for e in failures[-10:]])
                    if finding: findings.append(finding)
        return findings
