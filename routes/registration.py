# ============================================
# SCREEN: registration
# ============================================

from flask import Blueprint, request, jsonify, render_template
from sqlalchemy import text
from werkzeug.security import generate_password_hash
from your_db import engine

bp = Blueprint('registration', __name__)


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
                    INSERT INTO users (email, password_hash, first_name, last_name, email_verified)
                    VALUES (:email, :password_hash, :first_name, :last_name, false)
                    '''
                ),
                {
                    'email': email,
                    'password_hash': generate_password_hash(password),
                    'first_name': first_name,
                    'last_name': last_name,
                },
            )

        return jsonify(
            {
                'message': 'User account created successfully. Please verify your email address.'
            }
        ), 200

    except Exception:
        return jsonify({'error': 'Failed to create user account'}), 500
