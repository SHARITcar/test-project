# ============================================
# SCREEN: registration
# ============================================

import os
import re
from flask import Blueprint, request, jsonify, render_template
from supabase_client import supabase

bp = Blueprint('registration', __name__)

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,72}$'
)


def is_strong_password(password: str | None) -> bool:
    return bool(password and PASSWORD_PATTERN.match(password))


@bp.route('/register', methods=['GET'])
def registration_page():
    return render_template('registration.html')


@bp.route('/api/register_user', methods=['POST'])
def register_user():
    """
    Create a new user account via Supabase Auth.
    Supabase handles password hashing and sends the verification email automatically.
    first_name and last_name are stored in user metadata, then picked up by the
    handle_new_user trigger which writes them to public.profiles.
    """
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    first_name = (data.get('first_name') or '').strip()
    last_name = (data.get('last_name') or '').strip()

    if not email or not password or not confirm_password or not first_name or not last_name:
        return jsonify({'error': 'Missing required fields'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    if not is_strong_password(password):
        return jsonify({
            'error': 'Password must be 8-72 characters and include uppercase, lowercase, number, and symbol'
        }), 400

    try:
        redirect_url = f"{os.getenv('APP_BASE_URL', 'http://localhost:5000')}/email-verified"
        response = supabase.auth.sign_up({
            'email': email,
            'password': password,
            'options': {
                'data': {
                    'first_name': first_name,
                    'last_name': last_name,
                },
                'email_redirect_to': redirect_url,
            },
        })

        if response.user is None:
            return jsonify({'error': 'Registration failed'}), 400

        return jsonify({
            'message': 'Account created. Please check your email to verify your address.',
            'next_step': 'Check your inbox for the verification email.',
        }), 200

    except Exception as exc:
        msg = str(exc).lower()
        if 'already registered' in msg or 'already exists' in msg or 'user already' in msg:
            return jsonify({'error': 'Email already registered'}), 409
        if 'network is unreachable' in msg or 'connection' in msg or 'timeout' in msg:
            return jsonify({'error': 'Cannot reach authentication service. Please try again shortly.'}), 503
        return jsonify({'error': 'Registration failed', 'details': str(exc)}), 500
