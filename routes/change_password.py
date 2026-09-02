# ============================================
# SCREEN: change_password
# ============================================

import os
import re
import logging
from flask import Blueprint, request, jsonify
from supabase import create_client
from supabase_client import supabase, get_user_from_token, get_token_from_request

bp = Blueprint('change_password', __name__)
logger = logging.getLogger(__name__)

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$'
)


@bp.route('/api/change_password', methods=['POST'])
def change_password():
    """
    Change password with current password verification.
    Requires Authorization: Bearer <access_token> header.
    Re-authenticates with current_password to verify before updating.
    """
    access_token = get_token_from_request(request)
    if not access_token:
        return jsonify({'error': 'Authorization header required'}), 401

    user = get_user_from_token(access_token)
    if not user:
        return jsonify({'error': 'Invalid or expired session'}), 401

    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    refresh_token = data.get('refresh_token', '')

    if not current_password or not new_password or not confirm_password or not refresh_token:
        return jsonify({'error': 'Missing required fields'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'New password and confirm password do not match'}), 400

    if not PASSWORD_PATTERN.match(new_password):
        return jsonify({
            'error': 'Password must be 8-72 characters and include uppercase, lowercase, number, and symbol'
        }), 400

    try:
        # Re-authenticate to verify the current password is correct. This
        # creates its own throwaway session -- deliberately never used below,
        # so it doesn't become "the session that changed the password" and
        # cause Supabase to revoke the caller's real session instead of it.
        verify_resp = supabase.auth.sign_in_with_password({
            'email': user.email,
            'password': current_password,
        })

        if not verify_resp.session:
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Perform the actual update on the caller's own session (the one
        # whose tokens the browser already holds), so Supabase's "revoke
        # other sessions" behavior on password change treats this browser
        # tab as the session that made the change, not as another device.
        client = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_ANON_KEY"])
        client.auth.set_session(access_token, refresh_token)
        client.auth.update_user({'password': new_password})

        return jsonify({'message': 'Password updated successfully'}), 200

    except Exception as exc:
        msg = str(exc).lower()
        if 'invalid login credentials' in msg or 'invalid_credentials' in msg:
            return jsonify({'error': 'Current password is incorrect'}), 400
        logger.error(f"Change password error for {user.id}: {exc}")
        return jsonify({'error': 'Failed to update password'}), 500
