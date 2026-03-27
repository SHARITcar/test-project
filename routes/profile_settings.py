# ============================================
# SCREEN: profile_settings
# ============================================

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine

bp = Blueprint('profile_settings', __name__)


@bp.route('/api/demo/register_user', methods=['POST'])
def register_user():
    '''Create new user account with email verification requirement.'''

    email = request.json.get('email')
    password = request.json.get('password')

    query = text("""
        INSERT INTO users (email, password_hash, email_verified)
        VALUES (:email, :password_hash, false)
    """)

    with engine.connect() as conn:
        conn.execute(query, {'email': email, 'password_hash': password})
        conn.commit()

    return jsonify({"message": "Success confirmation with email address for verification step"})


@bp.route('/api/demo/verify_email', methods=['POST'])
def verify_email():
    '''Confirm user email ownership and activate account.'''

    verification_token = request.json.get('verification_token')

    query = text("""
        UPDATE users
        SET email_verified = true
        WHERE verification_token = :verification_token
    """)

    with engine.connect() as conn:
        conn.execute(query, {'verification_token': verification_token})
        conn.commit()

    return jsonify({"message": "Verification success status and redirect to onboarding"})


# Add routes for other functions/actions as needed
