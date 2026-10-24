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


def send_email(alert, config):
    check_config(config)

    msg = EmailMessage()
    msg["From"] = os.environ["SENTINELFORGE_GMAIL_FROM"]
    msg["To"] = config["email_to"]
    msg["Subject"] = (
        f"[SentinelForge {alert.severity.upper()}] {alert.title}"
    )[:180]

    msg.set_content(
        "SentinelForge Security Detection\n\n"
        f"Severity: {alert.severity}\n"
        f"Rule: {alert.rule}\n"
        f"Time: {alert.timestamp}\n"
        f"Title: {alert.title}\n\n"
        "Investigate locally. "
        "This alert is not proof of compromise."
    )

    ctx = ssl.create_default_context()
    errors = []
    for port in (465, 587):
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
                server.send_message(msg)
            return
        except smtplib.SMTPAuthenticationError:
            raise
        except (OSError, EOFError, smtplib.SMTPException) as exc:
            errors.append(f"{port}: {exc}")
    raise RuntimeError("SMTP delivery failed: " + "; ".join(errors))


def send(channel, alert, config):
    if channel != "email":
        raise ValueError("Unsupported notification channel.")
    return send_email(alert, config)
