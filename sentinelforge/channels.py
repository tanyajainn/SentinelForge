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


def format_alert(alert):
    if alert.rule == 'sentinelforge-self-test':
        return '[SentinelForge TEST] Email delivery check', f'Test email from the background agent.\nTime: {alert.timestamp}'
    title = ' '.join(alert.title.split())
    subject = f'[SentinelForge {alert.severity.upper()}] {title}'[:180]
    action = REVIEW_ACTIONS.get(alert.rule, 'Inspect the alert in the local database.')
    lines = [action, f'Time: {alert.timestamp}']
    evidence = alert.evidence[-1] if alert.evidence else {}
    if evidence.get('channel') and evidence.get('record_id') is not None:
        lines.append(f"Source: {evidence['channel']} | {alert.rule} | record {evidence['record_id']}")
    else:
        lines.append(f'Rule: {alert.rule}')
    return subject, '\n'.join(lines)


def send_email(alert, config):
    check_config(config)

    msg = EmailMessage()
    msg["From"] = os.environ["SENTINELFORGE_GMAIL_FROM"]
    msg["To"] = config["email_to"]
    subject, body = format_alert(alert)
    msg["Subject"] = subject
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
