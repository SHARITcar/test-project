from flask import Blueprint, request, jsonify
from sqlalchemy import text
from werkzeug.security import generate_password_hash
import hashlib
import logging
from your_db import engine

bp = Blueprint("password_reset_confirm", __name__)
logger = logging.getLogger(__name__)


@bp.route("/api/password-reset/confirm", methods=["POST"])
@bp.route("/api/reset_password", methods=["POST"])
def reset_password():
    """Confirm password reset with a valid token and set a new password."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400

    data = request.get_json() or {}
    reset_token = data.get("reset_token")
    new_password = data.get("new_password")

    if not isinstance(reset_token, str) or not reset_token.strip():
        return jsonify({"success": False, "error": "Reset token is required"}), 400

    if not isinstance(new_password, str) or not new_password:
        return jsonify({"success": False, "error": "New password is required"}), 400

    if len(new_password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400

    token_hash = hashlib.sha256(reset_token.strip().encode()).hexdigest()
    password_hash = generate_password_hash(new_password)

    try:
        with engine.begin() as connection:
            token_row = connection.execute(
                text(
                    """
                    SELECT token_id, user_id
                    FROM password_reset_tokens
                    WHERE token_hash = :token_hash
                      AND used_at IS NULL
                      AND expires_at > NOW()
                    LIMIT 1
                    """
                ),
                {"token_hash": token_hash},
            ).mappings().first()

            if not token_row:
                return jsonify({"success": False, "error": "Invalid or expired reset token"}), 400

            connection.execute(
                text(
                    """
                    UPDATE users
                    SET password_hash = :password_hash,
                        updated_at = NOW()
                    WHERE user_id = :user_id
                    """
                ),
                {"password_hash": password_hash, "user_id": token_row["user_id"]},
            )

            connection.execute(
                text(
                    """
                    UPDATE password_reset_tokens
                    SET used_at = NOW(),
                        invalidated_reason = 'used'
                    WHERE token_id = :token_id
                    """
                ),
                {"token_id": token_row["token_id"]},
            )

        return jsonify({"success": True, "message": "Password reset successfully"}), 200
    except Exception as e:
        logger.error(f"Failed to reset password: {str(e)}")
        return jsonify({"success": False, "error": "Failed to reset password"}), 500
