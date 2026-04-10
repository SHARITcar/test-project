# ============================================
# SCREEN: active_sessions
# ============================================
# Sessions are managed entirely by Supabase Auth (auth.sessions table).
# Listing or revoking individual sessions requires the service role key
# and is out of scope for the MVP.
# ============================================

from flask import Blueprint, request, jsonify
from supabase_client import get_user_from_token, get_token_from_request

bp = Blueprint("active_sessions", __name__)


@bp.route("/api/auth/me", methods=["GET"])
def get_current_user():
    """Return the identity of the currently authenticated user."""
    token = get_token_from_request(request)
    if not token:
        return jsonify({"error": "Missing Authorization header"}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired session"}), 401

    return jsonify({
        "id": str(user.id),
        "email": user.email,
    }), 200
