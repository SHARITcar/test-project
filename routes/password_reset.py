# ============================================
# SCREEN: password_reset
# ============================================

import os
import logging
from flask import Blueprint, request, jsonify
from supabase_client import supabase

bp = Blueprint('password_reset', __name__)
logger = logging.getLogger(__name__)


@bp.route('/api/password-reset/request', methods=['POST'])
def request_password_reset():
    """
    Trigger a password reset email via Supabase Auth.
    Always returns success to prevent email enumeration.
    Supabase sends the email and manages the reset token internally.
    """
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Content-Type must be application/json'}), 400

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()

    if not email:
        return jsonify({'success': False, 'message': 'Email address is required'}), 400

    redirect_url = f"{os.getenv('APP_BASE_URL', 'http://localhost:5000')}/password-reset-confirm"

    try:
        supabase.auth.reset_password_for_email(email, {'redirect_to': redirect_url})
    except Exception as exc:
        # Log but never expose — always return success to prevent enumeration
        logger.error(f"Password reset request error: {exc}")

    return jsonify({
        'success': True,
        'message': 'If an account with that email address exists, we have sent you a password reset link.',
    }), 200


@bp.route('/api/password-reset/status', methods=['GET'])
def get_password_reset_status():
    return jsonify({
        'success': True,
        'data': {
            'screen_name': 'password_reset',
            'available_actions': ['request_password_reset'],
            'connected_screens': ['login', 'password_reset_confirm'],
        },
    }), 200
