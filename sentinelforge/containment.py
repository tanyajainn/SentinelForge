"""Safe containment planning. No operating-system changes."""
from dataclasses import dataclass, asdict
from ipaddress import ip_address
from .threat_scoring import score_failed_logons


@dataclass(frozen=True)
class ContainmentDecision:
    approved: bool
    mode: str
    source_ip: str | None
    duration_minutes: int
    reason: str

    def to_dict(self):
        return asdict(self)


def plan_containment(
    source_ip,
    failure_count=None,
    logon_type=None,
    recurrence_windows=None,
    administrator_approved=False,
    duration_minutes=15,
):
    try:
        address = ip_address(source_ip)
        valid = (
            address.version == 4
            and address.is_global
            and not address.is_multicast
        )
    except (ValueError, TypeError):
        valid = False

    if not valid:
        return ContainmentDecision(
            False, "simulation", None, 0,
            "Source is not an eligible public IPv4 address."
        )

    score = score_failed_logons(
        str(address),
        failure_count,
        logon_type,
        recurrence_windows,
    )

    if score.missing_evidence:
        reason = "Insufficient evidence for containment."
    elif score.score < 70:
        reason = "Threat priority below containment review threshold."
    elif not administrator_approved:
        reason = "Administrator approval required."
    elif type(duration_minutes) is not int or not 1 <= duration_minutes <= 60:
        reason = "Containment duration must be 1-60 minutes."
    else:
        return ContainmentDecision(
            True, "simulation", str(address),
            duration_minutes,
            "Approved simulation only; no firewall action performed."
        )

    return ContainmentDecision(
        False, "simulation", str(address), 0, reason
    )
