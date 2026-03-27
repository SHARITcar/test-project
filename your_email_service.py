import os
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage

try:
    import certifi
except ImportError:  # pragma: no cover - optional dependency in local env
    certifi = None


def _is_truthy(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_ssl_context() -> ssl.SSLContext:
    verify_cert = _is_truthy(os.getenv("MAIL_VERIFY_CERT"), default=True)
    if verify_cert:
        ca_bundle = os.getenv("MAIL_CA_BUNDLE")
        if ca_bundle:
            return ssl.create_default_context(cafile=ca_bundle)
        if certifi is not None:
            return ssl.create_default_context(cafile=certifi.where())
        return ssl.create_default_context()

    context = ssl._create_unverified_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _send_email_via_smtp(to_email: str, subject: str, body: str) -> None:
    host = os.getenv("MAIL_HOST")
    port = int(os.getenv("MAIL_PORT", "587"))
    username = os.getenv("MAIL_USERNAME", "info@sharit.me")
    password = os.getenv("MAIL_PASSWORD")
    from_email = os.getenv("MAIL_FROM", username)
    use_tls = _is_truthy(os.getenv("MAIL_USE_TLS"), default=True)
    use_ssl = _is_truthy(os.getenv("MAIL_USE_SSL"), default=False)

    if not host or not password:
        raise RuntimeError("MAIL_HOST and MAIL_PASSWORD must be configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_email
    message["To"] = to_email
    message.set_content(body)
    ssl_context = _build_ssl_context()

    if use_ssl:
        with smtplib.SMTP_SSL(host, port, context=ssl_context) as server:
            server.login(username, password)
            server.send_message(message)
        return

    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        if use_tls:
            server.starttls(context=ssl_context)
            server.ehlo()
        server.login(username, password)
        server.send_message(message)


def _build_password_reset_url(reset_token: str) -> str:
    base_url = (os.getenv("APP_BASE_URL") or "http://localhost:5000").rstrip("/")
    return f"{base_url}/password-reset-confirm?token={reset_token}"


def send_password_reset_email(email: str, reset_token: str, expires_at: datetime) -> None:
    reset_url = _build_password_reset_url(reset_token)
    expires_label = expires_at.strftime("%d-%m-%Y %H:%M UTC")
    subject = "Reset je wachtwoord voor SHARIT"
    body = (
        "Hi,\n\n"
        "We hebben een verzoek ontvangen om je SHARIT-wachtwoord opnieuw in te stellen.\n"
        "Gebruik onderstaande link om een nieuw wachtwoord te kiezen:\n"
        f"{reset_url}\n\n"
        f"Deze link verloopt op {expires_label}.\n\n"
        "Heb je dit verzoek niet gedaan? Dan kun je deze e-mail negeren.\n\n"
        "Gedeelde groet,\n"
        "Team SHARIT"
    )
    _send_email_via_smtp(email, subject, body)


def send_password_changed_email(email: str, changed_at: datetime) -> None:
    changed_label = changed_at.strftime("%d-%m-%Y %H:%M UTC")
    subject = "Je SHARIT-wachtwoord is gewijzigd"
    body = (
        "Hi,\n\n"
        "Je wachtwoord voor SHARIT is succesvol gewijzigd.\n"
        f"Tijdstip van wijziging: {changed_label}.\n\n"
        "Heb je dit niet zelf gedaan? Neem dan direct contact met ons op via info@sharit.me.\n\n"
        "Gedeelde groet,\n"
        "Team SHARIT"
    )
    _send_email_via_smtp(email, subject, body)
