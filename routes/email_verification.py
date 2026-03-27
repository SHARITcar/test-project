import os
import smtplib
import ssl
from email.message import EmailMessage

try:
    import certifi
except ImportError:  # pragma: no cover - optional dependency in local env
    certifi = None

from flask import Blueprint, current_app, has_app_context, jsonify, redirect, request
from sqlalchemy import text
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from your_db import engine

bp = Blueprint("email_verification", __name__)


def hash_password(password: str) -> str:
    """Temporary placeholder until real password hashing is wired in."""
    return password


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


def _get_serializer() -> URLSafeTimedSerializer:
    secret_key = None
    if has_app_context():
        secret_key = current_app.config.get("SECRET_KEY")
    secret_key = secret_key or os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY is not configured")

    return URLSafeTimedSerializer(secret_key, salt="email-verification")


def generate_verification_token(email: str) -> str:
    return _get_serializer().dumps({"email": email})


def load_verification_token(token: str, max_age_seconds: int = 60 * 60 * 24) -> str:
    payload = _get_serializer().loads(token, max_age=max_age_seconds)
    email = payload.get("email")
    if not email:
        raise BadSignature("Token payload missing email")
    return email


def build_verification_url(email: str) -> str:
    base_url = (os.getenv("APP_BASE_URL") or "http://localhost:5000").rstrip("/")
    token = generate_verification_token(email)
    return f"{base_url}/verify-email?token={token}"


def build_verification_email(first_name: str, verification_url: str) -> dict[str, str]:
    safe_first_name = (first_name or "gebruiker").strip()
    safe_verification_url = (verification_url or "").strip()

    body = (
        f"Hi {safe_first_name},\n\n"
        "Welkom bij SHARIT, de eerste stap in gemakkelijk je auto delen.\n"
        "Om je account te activeren, moet je hieronder je e-mailadres bevestigen.\n"
        f"👉 {safe_verification_url}\n\n"
        "Heb je geen account aangemaakt? Dan kun je deze mail negeren.\n"
        "Tot snel in SHARIT.\n\n"
        "Gedeelde groet,\n"
        "Team SHARIT"
    )

    return {
        "subject": "Bevestig je e-mailadres voor SHARIT",
        "body": body,
    }


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


def send_verification_email(email: str, first_name: str) -> dict[str, str]:
    verification_url = build_verification_url(email)
    email_content = build_verification_email(first_name, verification_url)
    _send_email_via_smtp(email, email_content["subject"], email_content["body"])
    return email_content


def log_verification_event(email: str) -> None:
    """Temporary placeholder for analytics/audit logging."""
    return None


@bp.route("/api/email_verification/register_user", methods=["POST"])
def register_user():
    """Create new user account with email verification requirement."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name") or "gebruiker"

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    query = text(
        "INSERT INTO users (email, password_hash, email_verified, onboarding_completed, "
        "account_status, created_at, updated_at) "
        "VALUES (:email, :password_hash, false, false, 'active', NOW(), NOW())"
    )

    try:
        with engine.begin() as conn:
            conn.execute(
                query,
                {"email": email, "password_hash": hash_password(password)},
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    try:
        send_verification_email(email, first_name)
    except Exception as exc:
        current_app.logger.exception("Failed to send verification email")
        error_payload = {"error": "Failed to send verification email"}
        if current_app.debug:
            error_payload["details"] = str(exc)
        return jsonify(error_payload), 500

    return jsonify(
        {"message": "Success confirmation with email address for verification step"}
    ), 200


@bp.route("/api/verification_email_preview", methods=["POST"])
def verification_email_preview():
    data = request.get_json() or {}
    first_name = data.get("first_name") or "gebruiker"
    email = data.get("email") or "user@example.com"
    verification_url = data.get("verification_url") or build_verification_url(email)

    return jsonify(build_verification_email(first_name, verification_url)), 200


@bp.route("/verify-email", methods=["GET"])
def verify_email_from_link():
    token = request.args.get("token")
    if not token:
        return redirect("/email-verification?error=missing_token")

    try:
        email = load_verification_token(token)
    except SignatureExpired:
        return redirect("/email-verification?error=expired_token")
    except BadSignature:
        return redirect("/email-verification?error=invalid_token")

    query = text(
        "UPDATE users SET email_verified = true, updated_at = NOW() WHERE email = :email"
    )

    try:
        with engine.begin() as conn:
            result = conn.execute(query, {"email": email})
    except Exception as exc:
        current_app.logger.exception("Failed to verify email from link")
        error = "verification_failed"
        if current_app.debug:
            error = str(exc)
        return redirect(f"/email-verification?error={error}")

    if result.rowcount == 0:
        return redirect("/email-verification?error=account_not_found")

    try:
        log_verification_event(email)
    except Exception:
        current_app.logger.exception("Failed to log verification event")

    return redirect("/email-verified")


@bp.route("/api/verify_email", methods=["POST"])
def verify_email():
    """Confirm user email ownership and activate account."""
    data = request.get_json() or {}
    verification_token = data.get("verification_token")

    if not verification_token:
        return jsonify({"error": "Verification token is required"}), 400

    try:
        email = load_verification_token(verification_token)
    except SignatureExpired:
        return jsonify({"error": "Verification token has expired"}), 400
    except BadSignature:
        return jsonify({"error": "Invalid verification token"}), 400

    query = text("UPDATE users SET email_verified=true, updated_at = NOW() WHERE email=:email")

    try:
        with engine.begin() as conn:
            result = conn.execute(query, {"email": email})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if result.rowcount == 0:
        return jsonify({"error": "No account found for this email"}), 404

    try:
        log_verification_event(email)
    except Exception:
        return jsonify({"error": "Failed to log verification event"}), 500

    return jsonify(
        {"message": "Verification success status and redirect to onboarding"}
    ), 200
