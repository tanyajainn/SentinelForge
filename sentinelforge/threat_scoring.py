"""Explainable, read-only failed-logon threat scoring."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from .attribution import safe_source_ip


@dataclass(frozen=True)
class ThreatScore:
    score: int
    level: str
    confidence: str
    reasons: list[str]
    missing_evidence: list[str]
    automatic_block_allowed: bool = False

    def to_dict(self):
        return asdict(self)


def score_failed_logons(
    source_ip,
    failure_count=None,
    logon_type=None,
    recurrence_windows=None,
):
    reasons = []
    missing = []
    score = 0

    ip = safe_source_ip(source_ip)

    if not ip:
        missing.append("Verified public IPv4 source attribution")
        return ThreatScore(
            0, "insufficient_evidence", "low", reasons, missing
        )

    reasons.append("Public IPv4 address recorded; ownership not verified")

    if type(failure_count) is not int or failure_count < 1:
        missing.append("Reliable failed-login count")
    elif failure_count >= 20:
        score += 40
        reasons.append("20 or more failures in the observation window")
    elif failure_count >= 10:
        score += 30
        reasons.append("10 or more failures in the observation window")
    elif failure_count >= 5:
        score += 20
        reasons.append("5 or more failures in the observation window")
    else:
        score += 5
        reasons.append("Fewer than 5 failures")

    if type(logon_type) is not int:
        missing.append("Windows logon type")
    elif logon_type == 10:
        score += 25
        reasons.append("RemoteInteractive logon type (10)")
    elif logon_type == 3:
        score += 15
        reasons.append("Network logon type (3)")
    else:
        reasons.append(f"Logon type {logon_type}; no additional weight")

    if type(recurrence_windows) is not int or recurrence_windows < 0:
        missing.append("Recurring activity across distinct windows")
    elif recurrence_windows >= 3:
        score += 25
        reasons.append("Activity recorded in 3 or more windows")
    elif recurrence_windows >= 2:
        score += 15
        reasons.append("Activity recorded in 2 windows")

    if missing:
        confidence = "low"
    else:
        confidence = "moderate"

    if failure_count is None or type(failure_count) is not int or failure_count < 1:
        level = "insufficient_evidence"
    elif score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return ThreatScore(
        min(score, 100),
        level,
        confidence,
        reasons,
        missing,
    )
