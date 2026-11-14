"""Context-aware, offline Windows authentication analysis.

Uses observable evidence only. Never automatically blocks an IP.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import ipaddress


@dataclass
class AuthFinding:
    category: str
    severity: str
    score: int
    source_ip: str | None
    target_username: str | None
    reasons: list[str]
    recommended_action: str


def parse_time(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_ip(value):
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


class AuthenticationDetector:
    def __init__(
        self,
        short_window_minutes=10,
        long_window_minutes=120,
        threshold=5,
    ):
        self.short_window = timedelta(minutes=short_window_minutes)
        self.long_window = timedelta(minutes=long_window_minutes)
        self.threshold = threshold
        self.history = defaultdict(deque)
        self.last_alert = {}

    def process(self, event):
        if int(event.get("event_id", 0)) != 4625:
            return None

        timestamp = parse_time(event["timestamp"])
        ip = normalize_ip(event.get("source_ip"))
        account = str(event.get("target_username") or "unknown")
        logon_type = event.get("logon_type")

        # Keep sources separate. Unknown attribution is not proof of
        # a remote attack.
        source_key = ip or "unattributed"
        history = self.history[source_key]

        history.append((timestamp, account, logon_type))

        cutoff = timestamp - self.long_window
        while history and history[0][0] < cutoff:
            history.popleft()

        recent = [
            item for item in history
            if timestamp - item[0] <= self.short_window
        ]

        short_count = len(recent)
        long_count = len(history)
        distinct_accounts = len({item[1] for item in recent})

        reasons = []
        score = 0

        if short_count >= self.threshold:
            score += 35
            reasons.append(
                f"{short_count} failures in short observation window"
            )

        if short_count >= 10:
            score += 20
            reasons.append("High-frequency authentication failures")

        if distinct_accounts >= 5:
            score += 35
            reasons.append("Multiple accounts targeted")

        if long_count >= 8 and short_count < self.threshold:
            score += 40
            reasons.append("Repeated failures across a longer period")

        if logon_type == 10:
            score += 15
            reasons.append("Remote interactive authentication")

        if ip is None:
            reasons.append("Source IP unavailable or unverified")

        # Only suppress with independently established context.
        if event.get("verified_service_account") is True:
            score -= 30
            reasons.append(
                "Independently verified service-account context"
            )

        score = max(0, min(100, score))

        if score < 35:
            return None

        # Prevent duplicate alerts in the same short window.
        last = self.last_alert.get(source_key)
        if last and timestamp - last < self.short_window:
            return None

        self.last_alert[source_key] = timestamp

        return AuthFinding(
            category="authentication",
            severity="high" if score >= 70 else "medium",
            score=score,
            source_ip=ip,
            target_username=account,
            reasons=reasons,
            recommended_action=(
                "Investigate source, account, logon history and "
                "service ownership. Do not automatically block."
            ),
        )


def analyze_episode(events):
    detector = AuthenticationDetector()
    findings = []

    for event in events:
        result = detector.process(event)
        if result:
            findings.append(asdict(result))

    return findings
