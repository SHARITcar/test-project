import re
from datetime import datetime, UTC

from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import text
from werkzeug.security import generate_password_hash
import hashlib
import logging
from your_db import engine
from your_email_service import send_password_changed_email

bp = Blueprint("password_reset_confirm", __name__)
logger = logging.getLogger(__name__)
PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$'
)


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

    if not PASSWORD_PATTERN.match(new_password):
        return jsonify({
            "success": False,
            "error": "Password must be 8-72 characters and include uppercase, lowercase, number, and symbol",
        }), 400

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
                      AND expires_at > UTC_TIMESTAMP()
                    LIMIT 1
                    """
                ),
                {"token_hash": token_hash},
            ).mappings().first()

            if not token_row:
                return jsonify({"success": False, "error": "Invalid or expired reset token"}), 400

            user_row = connection.execute(
                text(
                    """
                    SELECT email
                    FROM users
                    WHERE user_id = :user_id
                    LIMIT 1
                    """
                ),
                {"user_id": token_row["user_id"]},
            ).mappings().first()

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

        if user_row and user_row.get("email"):
            try:
                send_password_changed_email(user_row["email"], datetime.now(UTC))
            except Exception as exc:
                current_app.logger.exception("Failed to send password changed confirmation email")
                return jsonify({
                    "success": False,
                    "error": "Password changed but failed to send confirmation email",
                    "details": str(exc) if current_app.debug else None,
                }), 500

        return jsonify({"success": True, "message": "Password reset successfully"}), 200
    except Exception as e:
        logger.error(f"Failed to reset password: {str(e)}")
        return jsonify({"success": False, "error": "Failed to reset password"}), 500
