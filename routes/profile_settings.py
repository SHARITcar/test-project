# ============================================
# SCREEN: profile_settings
# ============================================

import logging
import os
import uuid
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


@bp.route('/api/profile/photo', methods=['POST'])
def upload_profile_photo():
    """Upload a new profile photo and set it as the user's avatar_url."""
    token = get_token_from_request(request)
    if not token:
        return jsonify({'error': 'Authorization header required'}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({'error': 'Invalid or expired session'}), 401

    file = request.files.get('photo')
    if not file:
        return jsonify({'error': 'photo file is required'}), 400

    mimetype = (file.mimetype or '').lower()
    if not mimetype.startswith('image/'):
        return jsonify({'error': 'Only image uploads are allowed'}), 400

    try:
        client = db_for(token)
        bucket_name = os.getenv('AVATAR_BUCKET', 'avatars')
        extension = (file.filename.rsplit('.', 1)[-1] if file.filename and '.' in file.filename else 'jpg').lower()
        object_path = f"{user.id}/{uuid.uuid4()}.{extension}"

        upload_result = client.storage.from_(bucket_name).upload(
            object_path,
            file.read(),
            {'content-type': mimetype, 'upsert': 'true'},
        )
        if isinstance(upload_result, dict) and upload_result.get('error'):
            raise RuntimeError(upload_result['error'])

        public_result = client.storage.from_(bucket_name).get_public_url(object_path)
        if isinstance(public_result, dict):
            photo_url = public_result.get('publicURL') or public_result.get('public_url')
        else:
            photo_url = str(public_result)
        if not photo_url:
            raise RuntimeError('Could not resolve uploaded photo URL')

        result = (
            client.table('profiles')
            .update({'avatar_url': photo_url})
            .eq('id', str(user.id))
            .execute()
        )
        if not result.data:
            return jsonify({'error': 'Profile not found'}), 404

        return jsonify({'avatar_url': photo_url}), 200

    except Exception as exc:
        logger.error(f"Failed to upload profile photo for {user.id}: {exc}")
        return jsonify({'error': "We couldn't upload your photo right now. Please try again."}), 500


@bp.route('/api/profile/delete-account', methods=['POST'])
def delete_account():
    """Soft-delete the current user's account: mark it deleted so login is blocked,
    without touching the underlying Supabase Auth user (which would require the
    service-role key -- never used in request-scoped user code). Group history the
    user was part of stays intact for other members, matching the privacy policy."""
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
            .update({'account_status': 'deleted'})
            .eq('id', str(user.id))
            .execute()
        )
        if not result.data:
            return jsonify({'error': 'Profile not found'}), 404

        return jsonify({'message': 'Account deleted'}), 200

    except Exception as exc:
        logger.error(f"Failed to delete account for {user.id}: {exc}")
        return jsonify({'error': "We couldn't delete your account right now. Please try again."}), 500


_KNOWN_TIPS = {'trips_tip', 'costs_tip', 'dashboard_tip', 'insurance_banner'}


@bp.route('/api/profile/tips-seen', methods=['POST'])
def mark_tip_seen():
    """Mark a contextual onboarding tip as seen (shown only once per user, account-level)."""
    token = get_token_from_request(request)
    if not token:
        return jsonify({'error': 'Authorization header required'}), 401

    user = get_user_from_token(token)
    if not user:
        return jsonify({'error': 'Invalid or expired session'}), 401

    data = request.get_json() or {}
    tip = str(data.get('tip') or '').strip()
    if tip not in _KNOWN_TIPS:
        return jsonify({'error': f"tip must be one of {', '.join(sorted(_KNOWN_TIPS))}"}), 400

    try:
        client = db_for(token)
        current = (
            client.table('profiles')
            .select('seen_tips')
            .eq('id', str(user.id))
            .single()
            .execute()
        )
        if not current.data:
            return jsonify({'error': 'Profile not found'}), 404

        seen_tips = current.data.get('seen_tips') or []
        if tip not in seen_tips:
            seen_tips = seen_tips + [tip]
            client.table('profiles').update({'seen_tips': seen_tips}).eq('id', str(user.id)).execute()

        return jsonify({'seen_tips': seen_tips}), 200

    except Exception as exc:
        logger.error(f"Error marking tip seen for {user.id}: {exc}")
        return jsonify({'error': 'Failed to update tip state'}), 500
