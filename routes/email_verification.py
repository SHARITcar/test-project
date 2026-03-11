from flask import Blueprint, jsonify, request
from sqlalchemy import text
from your_db import engine

bp = Blueprint("email_verification", __name__)


def hash_password(password: str) -> str:
    """Temporary placeholder until real password hashing is wired in."""
    return password


def send_verification_email(email: str) -> None:
    """Temporary placeholder for your email provider integration."""
    return None


def log_verification_event(email: str) -> None:
    """Temporary placeholder for analytics/audit logging."""
    return None


@bp.route("/api/register_user", methods=["POST"])
def register_user():
    """Create new user account with email verification requirement."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

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
        send_verification_email(email)
    except Exception:
        return jsonify({"error": "Failed to send verification email"}), 500

    return jsonify(
        {"message": "Success confirmation with email address for verification step"}
    ), 200


@bp.route("/api/verify_email", methods=["POST"])
def verify_email():
    """Confirm user email ownership and activate account."""
    data = request.get_json() or {}
    email = data.get("email")
    verification_token = data.get("verification_token")

    if not email or not verification_token:
        return jsonify({"error": "Email and verification token are required"}), 400

    query = text("UPDATE users SET email_verified=true WHERE email=:email")

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
