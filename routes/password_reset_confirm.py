# ============================================
# SCREEN: password_reset_confirm
# ============================================
#
# Flow:
#   1. User clicks reset link in email
#   2. Supabase redirects to /password-reset-confirm with tokens in the URL hash:
#      #access_token=xxx&refresh_token=xxx&type=recovery
#   3. JavaScript on the page parses the hash and POSTs here with:
#      { access_token, refresh_token, new_password }
# ============================================

import os
import re
import logging
from flask import Blueprint, request, jsonify
from supabase import create_client
from supabase_client import get_user_from_token

bp = Blueprint("password_reset_confirm", __name__)
logger = logging.getLogger(__name__)

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$'
)


@bp.route("/api/password-reset/confirm", methods=["POST"])
@bp.route("/api/reset_password", methods=["POST"])
def reset_password():
    """Set a new password using the tokens from the Supabase recovery email."""
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type moet application/json zijn"}), 400

    data = request.get_json() or {}
    access_token = (data.get("access_token") or "").strip()
    refresh_token = (data.get("refresh_token") or "").strip()
    new_password = data.get("new_password", "")

    if not access_token or not refresh_token:
        return jsonify({"success": False, "error": "access_token en refresh_token zijn verplicht"}), 400

    if not isinstance(new_password, str) or not new_password:
        return jsonify({"success": False, "error": "Nieuw wachtwoord is verplicht"}), 400

    if not PASSWORD_PATTERN.match(new_password):
        return jsonify({
            "success": False,
            "error": "Wachtwoord moet 8-72 tekens bevatten met een hoofdletter, kleine letter, cijfer en symbool",
        }), 400

    # Verify the token is valid before attempting update
    user = get_user_from_token(access_token)
    if not user:
        return jsonify({"success": False, "error": "Ongeldige of verlopen resetlink"}), 400

    try:
        # Create a fresh per-request client and set the recovery session
        client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_ANON_KEY"])
        client.auth.set_session(access_token, refresh_token)
        client.auth.update_user({"password": new_password})

        return jsonify({"success": True, "message": "Wachtwoord succesvol gewijzigd"}), 200

    except Exception as exc:
        logger.error(f"Password reset confirm error for user {user.id}: {exc}")
        return jsonify({"success": False, "error": "Wachtwoord wijzigen mislukt"}), 500
