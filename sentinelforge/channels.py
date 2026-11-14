"""SentinelForge email notifications using Gmail SMTP."""

import os
import smtplib
import ssl
from email.message import EmailMessage


def enabled_channels(config):
    if config.get("mode") != "email":
        return []
    return ["email"]


def check_config(config):
    if config.get("mode") != "email":
        raise ValueError(
            "Only email notifications are supported. Run setup."
        )

    if not config.get("email_to"):
        raise ValueError("Email recipient is missing.")

    if not os.getenv("SENTINELFORGE_GMAIL_FROM"):
        raise ValueError("Gmail sender is not configured.")

    if not os.getenv("SENTINELFORGE_GMAIL_APP_PASSWORD"):
        raise ValueError("Gmail App Password is not configured.")


# The alert's persisted severity and title are authoritative, including old rows.
REVIEW_ACTIONS = {
    'event-4698': 'Open the task in Task Scheduler and check its author, trigger and program against the maintenance ticket.',
    'event-4722': 'Check which account was enabled and match the requesting administrator to an approved access request.',
    'event-4726': 'Identify the deleted account and verify the deletion with its owner or the offboarding ticket.',
    'event-4740': 'Check the locked account and caller computer. Ask the owner about recent password changes.',
    'event-1116': 'Review the threat and affected item in Defender Protection history.',
    'event-1117': 'Check Protection history for the remediation outcome.',
    'event-1118': 'Review the failed action and follow Defender’s remediation guidance.',
    'event-5001': 'Check whether real-time protection is back on and who disabled it.',
    'event-5007': 'Compare the old and new settings in the Defender event.',
    'event-5013': 'Check which protected setting Defender prevented from changing.',
    'event-4720': 'Verify who created the account and whether it was expected.',
    'event-4728': 'Verify the new group member and the access granted.',
    'event-4732': 'Verify the new group member and the access granted.',
    'event-4697': 'Check the service executable and who installed it.',
    'event-7045': 'Check the service executable against your recent software installs.',
    'event-1102': 'Identify who cleared the Security log and preserve available logs.',
    'event-4719': 'Review the changed audit policy and who authorized it.',
    'event-4625': 'Review the failed sign-ins for shared accounts or source addresses.',
}


FOLLOW_UP = {
    'event-1116': 'If Defender still shows an active threat, contact endpoint support with the detection reference.',
    'event-1117': 'If the affected item still needs action, ask endpoint support to verify remediation.',
    'event-1118': 'If remediation is still failing, send the record reference to endpoint support for containment review.',
    'event-5001': 'If protection is still off outside a maintenance window, contact endpoint support now.',
    'event-5013': 'If the blocked change is unexplained or repeats, ask endpoint support to review the initiating process.',
    'event-5007': 'If the change has no matching maintenance record, ask the endpoint owner to confirm it.',
    'event-4625': 'If failures continue or the account owner cannot explain them, send the record reference to identity support.',
    'event-4740': 'If lockouts recur, ask identity support to trace the source before unlocking the account again.',
    'event-1102': 'If the log clear was unplanned, preserve available copies and notify the incident lead.',
    'event-4719': 'If auditing was reduced without approval, contact the administrator responsible for audit policy.',
    'event-4698': 'If the task owner cannot explain it, preserve its definition and ask endpoint support to review it.',
}


def next_steps(rule):
    first = REVIEW_ACTIONS.get(rule, 'Review the alert and its source record in the local investigation export.')
    if rule in {'event-4720', 'event-4722', 'event-4726', 'event-4728', 'event-4732'}:
        follow = 'If the change was unexpected, give identity support the record reference and the access request you checked.'
    elif rule in {'event-4697', 'event-7045'}:
        follow = 'If the software owner cannot account for the service, ask endpoint support to review its origin.'
    else:
        follow = FOLLOW_UP.get(rule, 'If the event is unexplained, send the record reference to the endpoint owner.')
    return first, follow


PREVENTION = {
    'event-4625': 'Restrict remote sign-in access and enable MFA on the remote access service where supported.',
    'event-4740': 'Restrict remote sign-in access and enable MFA on the remote access service where supported.',
    'event-1116': 'Keep Defender security intelligence current and check the affected device for missing security updates.',
    'event-1117': 'Keep Defender security intelligence current and check the affected device for missing security updates.',
    'event-1118': 'Keep Defender security intelligence current and check the affected device for missing security updates.',
    'event-5001': 'Enable Defender tamper protection and limit who can change protection settings.',
    'event-5007': 'Enable Defender tamper protection and limit who can change protection settings.',
    'event-5013': 'Enable Defender tamper protection and limit who can change protection settings.',
    'event-4720': 'Limit account and group administration to designated admins and review privileged membership regularly.',
    'event-4722': 'Limit account and group administration to designated admins and review privileged membership regularly.',
    'event-4726': 'Limit account and group administration to designated admins and review privileged membership regularly.',
    'event-4728': 'Limit account and group administration to designated admins and review privileged membership regularly.',
    'event-4732': 'Limit account and group administration to designated admins and review privileged membership regularly.',
    'event-4697': 'Review who can install services or register privileged tasks and remove unnecessary access.',
    'event-7045': 'Review who can install services or register privileged tasks and remove unnecessary access.',
    'event-4698': 'Review who can install services or register privileged tasks and remove unnecessary access.',
    'event-1102': 'Forward security events to a separate collector and restrict who can change audit policy or clear logs.',
    'event-4719': 'Forward security events to a separate collector and restrict who can change audit policy or clear logs.',
}

INCIDENT_OUTCOMES = {
    'event-4625': 'Windows rejected these sign-ins. They may involve different accounts or devices. No later successful login has been linked.',
    'event-1116': 'Defender detected a threat. This record does not establish whether the item ran or was quarantined.',
    'event-1117': "Defender recorded a remediation action. The laptop's current protection status is unknown from this record alone.",
    'event-1118': 'Defender reported an error during remediation. This record does not confirm a successful retry.',
    'event-5001': 'Real-time protection was disabled at the recorded time. This event does not show when it resumed.',
    'event-5007': 'A Defender setting changed. Whether protection was weakened depends on the old and new values.',
    'event-5013': "Defender blocked the attempted settings change. The initiating person's intent is unknown.",
    'event-4698': 'Windows registered a scheduled task. This event does not show that its program ran.',
    'event-4697': 'Windows recorded a service installation. Whether the service ran or was authorized requires separate evidence.',
    'event-7045': 'Windows recorded a service installation. Whether the service ran or was authorized requires separate evidence.',
    'event-4720': 'Windows created an account. This event does not establish that anyone signed in with it.',
    'event-4722': 'Windows enabled an account. Subsequent use is unknown.',
    'event-4726': 'Windows deleted an account. The record alone does not establish why the deletion was authorized.',
    'event-4740': 'Windows locked the account. Saved credentials, typing mistakes, or password guessing can cause this pattern.',
    'event-4728': 'Windows added a member to a global security group. Subsequent use of that access is unknown.',
    'event-4732': 'Windows added a member to a local security group. Subsequent use of that access is unknown.',
    'event-1102': 'The local Security log was cleared. Previously forwarded copies may still exist.',
    'event-4719': 'Windows changed its audit policy. The effect on future logging depends on which settings changed.',
}


def format_source_login_alert(alert):
    """Create a privacy-conscious, investigation-first login alert."""
    from .threat_assessment import assess

    assessment = assess({
        "rule": alert.rule,
        "severity": alert.severity,
        "timestamp": alert.timestamp,
        "evidence": alert.evidence,
    })

    subject = f"[SentinelForge {alert.severity.upper()}] Suspicious failed logons"
    evidence = alert.evidence[0] if alert.evidence and isinstance(alert.evidence[0], dict) else {}

    lines = [
        "Suspicious failed Windows sign-ins detected.",
        f"Observed: {alert.timestamp}",
        f"Source IP: {assessment.get('source_ip') or 'unverified'}",
        f"Target account: {assessment.get('target_username') or 'not recorded'}",
        f"Logon type: {assessment.get('logon_type') if assessment.get('logon_type') is not None else 'unknown'}",
        f"First failure: {assessment.get('first_failure_at') or 'unknown'}",
        f"Last failure: {assessment.get('last_failure_at') or 'unknown'}",
        "",
        "Assessment: " + assessment["classification"],
        "Recorded outcome: Windows rejected the observed sign-ins. "
        "This does not establish whether any later login succeeded.",
        "",
        "Recommended action: " + assessment["recommendation"],
        "Firewall action: No automatic blocking. Independently verify the "
        "source before considering a manually approved response.",
    ]

    if evidence.get("channel") and evidence.get("record_id") is not None:
        lines.append(
            f"Evidence reference: {evidence['channel']} | "
            f"record {evidence['record_id']}"
        )

    return subject, "\n".join(lines)


def format_alert(alert):
    if alert.rule == "event-4625-source":
        return format_source_login_alert(alert)

    if alert.rule in {"monitor-outage", "monitor-recovery"}:
        detail = alert.evidence[0]
        channel = detail["channel"]
        impact = {
            "Security": "Sign-in, account and audit-policy alerts may be delayed.",
            "System": "System-log service installation alerts may be delayed.",
            "Microsoft-Windows-Windows Defender/Operational":
                "Defender detection and remediation alerts may be delayed.",
        }.get(channel, "Alerts based on this log may be delayed.")
        subject = f"[SentinelForge {alert.severity.upper()}] {alert.title}"
        if alert.rule == "monitor-outage":
            body = (
                f"SentinelForge could not read {channel} on three consecutive checks.\n"
                f"First failure: {detail['started']}\n"
                f"Last successful read: {detail.get('last_success') or 'none recorded'}\n\n"
                f"Impact: {impact}\n"
                "Next step: Run SentinelForge status and review the error for this channel. "
                "If it says access denied, check the task account's read permission for that log."
            )
        else:
            body = (
                f"SentinelForge successfully read {channel} again.\n"
                f"First failure: {detail['started']}\nRead restored: {alert.timestamp}\n\n"
                "Monitoring has resumed. Records that expired from Windows during the outage "
                "may be unavailable."
            )
        return subject, body

    if alert.rule == 'sentinelforge-self-test':
        return '[SentinelForge TEST] Email delivery check', f'Test email from the background agent.\nTime: {alert.timestamp}'
    title = ' '.join(alert.title.split())
    subject = f'[SentinelForge {alert.severity.upper()}] {title}'[:180]
    action, follow = next_steps(alert.rule)
    evidence = alert.evidence[-1] if alert.evidence else {}
    outcome = INCIDENT_OUTCOMES.get(alert.rule, 'No later outcome is available in this alert.')
    if alert.rule == 'event-1117' and (evidence.get('action_name') or '').strip().lower() == 'quarantine':
        outcome = 'Defender reported quarantining the affected item.'
    lines = [f'What happened: {title}', f'Observed: {alert.timestamp}']
    if evidence.get('first_failure_at'):
        lines.append(f"First failure in this burst: {evidence['first_failure_at']}")
    if evidence.get('detected_record'):
        lines.append(f"Earlier detection: {evidence['detected_at']} (record {evidence['detected_record']}, same Defender detection ID)")
    lines.extend(['', 'Recorded outcome: ' + outcome])
    if evidence.get('channel') and evidence.get('record_id') is not None:
        lines.append(f"Source: {evidence['channel']} | {alert.rule} | record {evidence['record_id']}")
    else:
        lines.append(f'Rule: {alert.rule}')
    lines.extend(['', 'What to check: ' + action, follow])
    if alert.rule in PREVENTION:
        lines.extend(["", "Prevention: " + PREVENTION[alert.rule]])
    return subject, '\n'.join(lines)


def send_email(alert, config):
    check_config(config)

    msg = EmailMessage()
    msg["From"] = os.environ["SENTINELFORGE_GMAIL_FROM"]
    import sys
    from importlib.util import find_spec
    if getattr(sys, "frozen", False) and find_spec("sentinelforge._local_mail_policy") is not None:
        from ._local_mail_policy import RECIPIENT
        msg["To"] = RECIPIENT
    else:
        msg["To"] = config["email_to"]
    subject, body = format_alert(alert)
    host = os.environ.get("COMPUTERNAME") or "Windows laptop"
    msg["Subject"] = f"{subject} | {host}"
    msg.set_content(body)

    ctx = ssl.create_default_context()
    errors = []
    for port in (465, 587):
        submission_started = False
        accepted = False
        try:
            if port == 465:
                smtp = smtplib.SMTP_SSL(
                    "smtp.gmail.com", 465, context=ctx, timeout=20
                )
            else:
                smtp = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
            with smtp as server:
                if port == 587:
                    server.ehlo()
                    server.starttls(context=ctx)
                    server.ehlo()
                server.login(
                    os.environ["SENTINELFORGE_GMAIL_FROM"],
                    os.environ["SENTINELFORGE_GMAIL_APP_PASSWORD"],
                )
                submission_started = True
                server.send_message(msg)
                accepted = True
            return
        except smtplib.SMTPAuthenticationError:
            raise
        except (OSError, EOFError, smtplib.SMTPException) as exc:
            # QUIT can fail after Gmail has already accepted the message.
            if accepted:
                return
            if submission_started:
                # The final DATA response may have been lost. Leave the alert
                # queued for normal backoff instead of immediately resending.
                raise
            errors.append(f"{port}: {exc}")
    raise RuntimeError("SMTP delivery failed: " + "; ".join(errors))


def send(channel, alert, config):
    if channel != "email":
        raise ValueError("Unsupported notification channel.")
    return send_email(alert, config)
