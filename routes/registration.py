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
        return jsonify({'error': 'Content-Type moet application/json zijn'}), 400

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    first_name = (data.get('first_name') or '').strip()
    last_name = (data.get('last_name') or '').strip()

    if not email or not password or not confirm_password or not first_name or not last_name:
        return jsonify({'error': 'Verplichte velden ontbreken'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Wachtwoorden komen niet overeen'}), 400

    if not is_strong_password(password):
        return jsonify({
            'error': 'Wachtwoord moet 8-72 tekens bevatten met een hoofdletter, kleine letter, cijfer en symbool'
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
            return jsonify({'error': 'Registreren mislukt'}), 400

        # Supabase's anti-enumeration protection doesn't raise for a sign_up
        # with an email that already has a confirmed account — it returns a
        # look-alike user with an empty identities list and sends no email.
        # Without this check we'd tell the user we sent a verification email
        # that never went out.
        if not getattr(response.user, 'identities', None):
            return jsonify({
                'error': "Dit e-mailadres is al in gebruik. Log in of gebruik 'wachtwoord vergeten'."
            }), 409

        return jsonify({
            'message': 'Account aangemaakt. Controleer je e-mail om je adres te bevestigen.',
            'next_step': 'Bekijk je inbox voor de verificatiemail.',
        }), 200

    except Exception as exc:
        msg = str(exc).lower()
        if 'already registered' in msg or 'already exists' in msg or 'user already' in msg:
            return jsonify({'error': 'E-mailadres is al geregistreerd'}), 409
        if 'network is unreachable' in msg or 'connection' in msg or 'timeout' in msg:
            return jsonify({'error': 'Kan de registratieservice niet bereiken. Probeer het straks opnieuw.'}), 503
        return jsonify({'error': 'Registreren mislukt', 'details': str(exc)}), 500
