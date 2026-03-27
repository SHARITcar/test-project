# ============================================
# SCREEN: registration
# ============================================

import re

from flask import Blueprint, request, jsonify, render_template, current_app
from sqlalchemy import text
from werkzeug.security import generate_password_hash
from routes.email_verification import send_verification_email
from your_db import engine

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
    '''Create new user account with email verification requirement.'''

    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 400

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')
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
        with engine.begin() as connection:
            # Check uniqueness before insert so we can return a clear error.
            existing_user = connection.execute(
                text('SELECT 1 FROM users WHERE email = :email LIMIT 1'),
                {'email': email},
            ).first()

            if existing_user:
                return jsonify({'error': 'Email already registered'}), 409

            connection.execute(
                text(
                    '''
                    INSERT INTO users (
                        user_id,
                        email,
                        password_hash,
                        first_name,
                        last_name,
                        email_verified,
                        onboarding_completed,
                        account_status,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        UUID(),
                        :email,
                        :password_hash,
                        :first_name,
                        :last_name,
                        false,
                        false,
                        'active',
                        NOW(),
                        NOW()
                    )
                    '''
                ),
                {
                    'email': email,
                    'password_hash': generate_password_hash(password),
                    'first_name': first_name,
                    'last_name': last_name,
                },
            )

        try:
            send_verification_email(email, first_name)
        except Exception as exc:
            current_app.logger.exception('Failed to send verification email after registration')
            error_payload = {'error': 'Failed to send verification email'}
            if current_app.debug:
                error_payload['details'] = str(exc)
            return jsonify(error_payload), 500

        return jsonify(
            {
                'message': 'User account created successfully. Please verify your email address.',
                'next_step': 'Check your inbox for the verification email.'
            }
        ), 200

    except Exception as exc:
        current_app.logger.exception('Failed to create user account')
        error_payload = {'error': 'Failed to create user account'}
        if current_app.debug:
            error_payload['details'] = str(exc)
        return jsonify(error_payload), 500
