# ============================================
# SCREEN: onboarding
# ============================================

import logging
from flask import Blueprint, request, jsonify
from supabase_client import db_for, get_user_from_token, get_token_from_request

bp = Blueprint("onboarding", __name__)
logger = logging.getLogger(__name__)


@bp.route("/api/complete_onboarding", methods=["POST"])
def complete_onboarding():
    """
    Mark user onboarding as complete and optionally set an avatar URL.
    Requires Authorization: Bearer <access_token> header.

    Avatar upload is handled separately (e.g. Supabase Storage or external CDN).
    Send the resulting URL in the request body as avatar_url.
    """
    token = get_token_from_request(request)
    if not token:
        return jsonify({"error": "Authorization header required"}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired session"}), 401

    data = request.get_json() or {}
    avatar_url = data.get("avatar_url")

    update_data = {"onboarding_completed": True}
    if avatar_url:
        update_data["avatar_url"] = str(avatar_url).strip()

    try:
        result = (
            db_for(token)
            .table("profiles")
            .update(update_data)
            .eq("id", str(user.id))
            .execute()
        )

        if not result.data:
            return jsonify({"error": "Profile not found"}), 404

        profile = result.data[0]
        profile["id"] = str(user.id)
        profile["email"] = user.email

        return jsonify({
            "message": "Onboarding completed successfully",
            "user_profile": profile,
        }), 200

    except Exception as exc:
        logger.error(f"Onboarding error for {user.id}: {exc}")
        return jsonify({"error": "Failed to complete onboarding"}), 500
