from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine  # change this import to your actual engine location

bp = Blueprint("dashboard", __name__)

@bp.route("/api/get_user_profile", methods=["GET"])
def get_user_profile():
    """Fetch current user account details for profile display."""
    session_token = request.headers.get("Authorization")
    if not session_token:
        return jsonify({"error": "Missing session token"}), 401

    query = text("""
        SELECT user_id, email, first_name, last_name, avatar_url, created_at
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
        result = conn.execute(query, {"token": session_token}).mappings().first()

    if not result:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user_profile": dict(result)}), 200


@bp.route("/api/logout_user", methods=["POST"])
def logout_user():
    """Explicitly end current user session."""
    session_token = request.headers.get("Authorization")
    if not session_token:
        return jsonify({"error": "Missing session token"}), 401

    query = text("""
        UPDATE user_sessions
        SET revoked_at = CURRENT_TIMESTAMP,
            revoked_reason = 'user_logout'
        WHERE token_hash = :token
          AND revoked_at IS NULL
    """)

    with engine.begin() as conn:
        conn.execute(query, {"token": session_token})

    return jsonify({"message": "Logout successful"}), 200
