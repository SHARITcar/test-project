import hashlib

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine  # change this import to your actual engine location

bp = Blueprint("dashboard", __name__)


def _extract_token_hash() -> str | None:
    authorization = request.headers.get("Authorization", "").strip()
    if not authorization:
        return None

    if authorization.lower().startswith("bearer "):
        authorization = authorization[7:].strip()

    if not authorization:
        return None

    return hashlib.sha256(authorization.encode()).hexdigest()

@bp.route("/api/get_user_profile", methods=["GET"])
def get_user_profile():
    """Fetch current user account details for profile display."""
    token_hash = _extract_token_hash()
    if not token_hash:
        return jsonify({"error": "Missing session token"}), 401

    query = text("""
        SELECT user_id, email, first_name, last_name, avatar_url, created_at, onboarding_completed
        FROM users
        WHERE user_id = (
            SELECT user_id
            FROM user_sessions
            WHERE token_hash = :token
              AND revoked_at IS NULL
            LIMIT 1
        )
    """)

    with engine.connect() as conn:
        result = conn.execute(query, {"token": token_hash}).mappings().first()

    if not result:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user_profile": dict(result)}), 200


@bp.route("/api/logout_user", methods=["POST"])
def logout_user():
    """Explicitly end current user session."""
    token_hash = _extract_token_hash()
    if not token_hash:
        return jsonify({"error": "Missing session token"}), 401

    query = text("""
        UPDATE user_sessions
        SET revoked_at = CURRENT_TIMESTAMP,
            revoked_reason = 'user_logout'
        WHERE token_hash = :token
          AND revoked_at IS NULL
    """)

    with engine.begin() as conn:
        conn.execute(query, {"token": token_hash})

    return jsonify({"message": "Logout successful"}), 200
