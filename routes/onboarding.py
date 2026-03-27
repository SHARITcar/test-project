import hashlib

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine

bp = Blueprint("onboarding", __name__)


def upload_avatar_file(avatar_file):
    """
    Placeholder for secure avatar upload integration.
    Return avatar URL string after successful upload.
    """
    # Replace this with real upload logic (S3, Cloudinary, etc.)
    return None


def _extract_token_hash() -> str | None:
    authorization = request.headers.get("Authorization", "").strip()
    if not authorization:
        return None

    if authorization.lower().startswith("bearer "):
        authorization = authorization[7:].strip()

    if not authorization:
        return None

    return hashlib.sha256(authorization.encode()).hexdigest()


@bp.route("/api/complete_onboarding", methods=["POST"])
def complete_onboarding():
    """Mark user as onboarded and optionally save avatar URL."""
    data = request.get_json() or {}
    token_hash = _extract_token_hash()
    user_id = data.get("user_id")
    if not user_id and token_hash:
        with engine.connect() as connection:
            session_user = connection.execute(
                text(
                    "SELECT user_id FROM user_sessions "
                    "WHERE token_hash = :token_hash AND revoked_at IS NULL "
                    "AND expires_at > NOW() "
                    "LIMIT 1"
                ),
                {"token_hash": token_hash},
            ).mappings().first()
        if session_user:
            user_id = session_user["user_id"]

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    avatar_file = data.get("avatar_file")

    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE users "
                    "SET onboarding_completed = true, updated_at = NOW() "
                    "WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            )

            if avatar_file:
                avatar_url = upload_avatar_file(avatar_file)
                if avatar_url:
                    connection.execute(
                        text(
                            "UPDATE users "
                            "SET avatar_url = :avatar_url, updated_at = NOW() "
                            "WHERE user_id = :user_id"
                        ),
                        {"avatar_url": avatar_url, "user_id": user_id},
                    )

            result = connection.execute(
                text(
                    "SELECT user_id, email, first_name, last_name, "
                    "avatar_url, onboarding_completed "
                    "FROM users WHERE user_id = :user_id"
                ),
                {"user_id": user_id},
            ).mappings().first()

        if not result:
            return jsonify({"error": "User not found"}), 404

        return jsonify(
            {
                "message": "Onboarding completed successfully",
                "user_profile": dict(result),
            }
        ), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
