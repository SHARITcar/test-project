# ============================================
# SCREEN: profile_settings
# ============================================

import logging
from flask import Blueprint, request, jsonify
from supabase_client import db_for, get_user_from_token, get_token_from_request

bp = Blueprint('profile_settings', __name__)
logger = logging.getLogger(__name__)

_UPDATABLE_FIELDS = {'first_name', 'last_name', 'avatar_url'}


@bp.route('/api/profile_settings', methods=['GET'])
def get_profile_settings():
    """Fetch the current user's full profile for the settings screen."""
    token = get_token_from_request(request)
    if not token:
        return jsonify({'error': 'Authorization header required'}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({'error': 'Invalid or expired session'}), 401

    try:
        result = (
            db_for(token)
            .table('profiles')
            .select('first_name, last_name, avatar_url, onboarding_completed, created_at, updated_at')
            .eq('id', str(user.id))
            .single()
            .execute()
        )

        if not result.data:
            return jsonify({'error': 'Profile not found'}), 404

        profile = result.data
        profile['id'] = str(user.id)
        profile['email'] = user.email

        return jsonify({'profile': profile}), 200

    except Exception as exc:
        logger.error(f"Error fetching profile settings for {user.id}: {exc}")
        return jsonify({'error': 'Failed to fetch profile'}), 500


@bp.route('/api/profile_settings', methods=['PUT'])
def update_profile_settings():
    """Update editable profile fields (first_name, last_name, avatar_url)."""
    token = get_token_from_request(request)
    if not token:
        return jsonify({'error': 'Authorization header required'}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({'error': 'Invalid or expired session'}), 401

    data = request.get_json() or {}
    update_data = {k: v for k, v in data.items() if k in _UPDATABLE_FIELDS}

    if not update_data:
        return jsonify({'error': 'No valid fields to update'}), 400

    for field in ('first_name', 'last_name'):
        if field in update_data:
            update_data[field] = (update_data[field] or '').strip()
            if not update_data[field]:
                return jsonify({'error': f'{field} cannot be empty'}), 400

    try:
        result = (
            db_for(token)
            .table('profiles')
            .update(update_data)
            .eq('id', str(user.id))
            .execute()
        )

        if not result.data:
            return jsonify({'error': 'Profile not found'}), 404

        return jsonify({'message': 'Profile updated', 'profile': result.data[0]}), 200

    except Exception as exc:
        logger.error(f"Error updating profile for {user.id}: {exc}")
        return jsonify({'error': 'Failed to update profile'}), 500
