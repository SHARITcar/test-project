# ============================================
# SCREEN: login
# ============================================

import logging
from flask import Blueprint, request, jsonify
from supabase_client import supabase, db_for, get_user_from_token, get_token_from_request

bp = Blueprint('login', __name__)
logger = logging.getLogger(__name__)


@bp.route('/api/auth/login', methods=['POST'])
def authenticate_user():
    """
    Authenticate via Supabase Auth. Returns access_token and refresh_token.
    The client stores these and sends access_token as Authorization: Bearer <token>
    on all subsequent authenticated requests.
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid JSON payload'}), 400

    if not data:
        return jsonify({'success': False, 'error': 'Missing request data'}), 400

    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password are required'}), 400

    if len(password) > 1000:
        return jsonify({'success': False, 'error': 'Password too long'}), 400

    try:
        response = supabase.auth.sign_in_with_password({'email': email, 'password': password})

        user = response.user
        session = response.session

        if not user or not session:
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Fetch app profile with the user's JWT so RLS is satisfied
        profile_resp = (
            db_for(session.access_token)
            .table('profiles')
            .select('first_name, last_name, avatar_url, onboarding_completed, account_status')
            .eq('id', str(user.id))
            .single()
            .execute()
        )
        profile = profile_resp.data or {}

        if profile.get('account_status') == 'suspended':
            return jsonify({'success': False, 'error': 'Account suspended. Please contact support.'}), 403
        if profile.get('account_status') == 'deleted':
            return jsonify({'success': False, 'error': 'Account not found.'}), 404

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'data': {
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'expires_at': session.expires_at,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': profile.get('first_name', ''),
                    'last_name': profile.get('last_name', ''),
                    'avatar_url': profile.get('avatar_url'),
                    'onboarding_completed': profile.get('onboarding_completed', False),
                },
            },
        }), 200

    except Exception as exc:
        msg = str(exc).lower()
        if 'invalid login credentials' in msg or 'invalid_credentials' in msg:
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
        if 'email not confirmed' in msg:
            return jsonify({
                'success': False,
                'error': 'Please verify your email before logging in.',
                'action_required': 'email_verification',
            }), 403
        if 'network is unreachable' in msg or 'connection' in msg or 'timeout' in msg:
            logger.error(f"Supabase unreachable for {email}: {exc}")
            return jsonify({'success': False, 'error': 'Cannot reach authentication service. Please try again shortly.'}), 503
        logger.error(f"Login error for {email}: {exc}")
        return jsonify({'success': False, 'error': 'Authentication service unavailable'}), 500


@bp.route('/api/auth/refresh', methods=['POST'])
def refresh_session():
    """Exchange a refresh_token for a new access_token."""
    data = request.get_json() or {}
    refresh_token = (data.get('refresh_token') or '').strip()

    if not refresh_token:
        return jsonify({'success': False, 'error': 'refresh_token is required'}), 400

    try:
        response = supabase.auth.refresh_session(refresh_token)
        session = response.session

        if not session:
            return jsonify({'success': False, 'error': 'Invalid or expired refresh token'}), 401

        return jsonify({
            'success': True,
            'data': {
                'access_token': session.access_token,
                'refresh_token': session.refresh_token,
                'expires_at': session.expires_at,
            },
        }), 200

    except Exception as exc:
        logger.error(f"Token refresh error: {exc}")
        return jsonify({'success': False, 'error': 'Failed to refresh session'}), 500
