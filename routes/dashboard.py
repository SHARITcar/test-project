# ============================================
# SCREEN: dashboard
# ============================================

import logging
from flask import Blueprint, request, jsonify
from supabase_client import db_for, get_user_from_token, get_token_from_request

bp = Blueprint("dashboard", __name__)
logger = logging.getLogger(__name__)


@bp.route("/api/get_user_profile", methods=["GET"])
def get_user_profile():
    """
    Fetch the current user's profile from public.profiles.
    Requires Authorization: Bearer <access_token> header.
    """
    token = get_token_from_request(request)
    if not token:
        return jsonify({"error": "Missing Authorization header"}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired session"}), 401

    try:
        result = (
            db_for(token)
            .table("profiles")
            .select("first_name, last_name, avatar_url, onboarding_completed, active_group_id, seen_tips, created_at")
            .eq("id", str(user.id))
            .single()
            .execute()
        )

        if not result.data:
            return jsonify({"error": "Profile not found"}), 404

        profile = result.data
        profile["id"] = str(user.id)
        profile["email"] = user.email

        return jsonify({"user_profile": profile}), 200

    except Exception as exc:
        logger.error(f"Error fetching profile for {user.id}: {exc}")
        return jsonify({"error": "Failed to fetch profile"}), 500


@bp.route("/api/logout_user", methods=["POST"])
def logout_user():
    """
    Client-side logout endpoint.
    The client must discard its stored access_token and refresh_token.
    Tokens expire naturally (access: 1h, refresh: configurable in Supabase dashboard).
    """
    token = get_token_from_request(request)
    if not token:
        return jsonify({"error": "Missing Authorization header"}), 401

    # Verify the token is still valid before confirming logout
    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired session"}), 401

    return jsonify({"message": "Logout successful"}), 200
