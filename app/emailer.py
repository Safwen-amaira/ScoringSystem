from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from .models import ScoringRequest


def send_recommendation_mail(request: ScoringRequest, subject: str, text_body: str, html_body: str) -> bool:
    recipient = request.analyst_email
    if not recipient:
        return False

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "25"))
    smtp_sender = os.getenv("SMTP_SENDER", "soc-automation@example.local")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not smtp_host:
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_sender
    message["To"] = recipient
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as client:
        if smtp_username and smtp_password:
            client.starttls()
            client.login(smtp_username, smtp_password)
        client.send_message(message)
    return True
