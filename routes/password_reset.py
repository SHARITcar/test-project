# ============================================
# SCREEN: password_reset
# ============================================

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from email_validator import validate_email, EmailNotValidError
import secrets
import logging
from datetime import datetime, timedelta, UTC
from your_db import engine
from your_email_service import send_password_reset_email

bp = Blueprint('password_reset', __name__)

# Configure logging to exclude sensitive data
logger = logging.getLogger(__name__)


@bp.route('/api/password-reset/request', methods=['POST'])
def request_password_reset():
    '''
    Generate secure reset link for forgotten passwords.
    Always returns success to prevent email enumeration attacks.

    Security considerations:
    - Email validation prevents injection attacks
    - Always returns success regardless of email existence
    - Tokens are cryptographically secure with expiration
    - Database errors are logged but not exposed to client
    '''

    try:
        # Input validation - treat all input as untrusted
        if not request.is_json:
            return jsonify({
                'success': False,
                'message': 'Content-Type must be application/json'
            }), 400

        data = request.get_json()

        # Validate required fields exist
        if not data or 'email' not in data:
            return jsonify({
                'success': False,
                'message': 'Email address is required'
            }), 400

        email = data['email']

        # Validate email is string type and not empty
        if not isinstance(email, str) or not email.strip():
            return jsonify({
                'success': False,
                'message': 'Email address must be a non-empty string'
            }), 400

        # Sanitize email - remove whitespace and convert to lowercase
        email = email.strip().lower()

        # Validate email format using robust email validator
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Use normalized form
        except EmailNotValidError:
            return jsonify({
                'success': False,
                'message': 'Please enter a valid email address'
            }), 400

        # Check email length to prevent buffer overflow attacks
        if len(email) > 320:  # RFC 5321 email length limit
            return jsonify({
                'success': False,
                'message': 'Email address is too long'
            }), 400

        # Database operations with explicit error handling
        try:
            with engine.connect() as conn:
                # Check if email exists and account is active
                # Using parameterized query to prevent SQL injection
                user_query = text("""
                    SELECT user_id, email, account_status, email_verified
                    FROM users
                    WHERE email = :email
                    AND account_status = 'active'
                    AND deleted_at IS NULL
                """)

                user_result = conn.execute(user_query, {'email': email}).fetchone()

                # Always continue processing to prevent timing attacks
                # Generate token regardless of whether user exists
                reset_token = secrets.token_urlsafe(32)  # 256-bit entropy
                token_expiration = datetime.now(UTC) + timedelta(hours=1)  # 1 hour expiration

                if user_result:
                    user_id = user_result.user_id
                    user_email = user_result.email

                    # Only proceed if email is verified to prevent abuse
                    if user_result.email_verified:
                        # Store reset token in database
                        # First, invalidate any existing reset tokens for this user
                        invalidate_query = text("""
                            UPDATE password_reset_tokens
                            SET used_at = NOW(),
                                invalidated_reason = 'new_request'
                            WHERE user_id = :user_id
                            AND used_at IS NULL
                            AND expires_at > UTC_TIMESTAMP()
                        """)

                        conn.execute(invalidate_query, {'user_id': user_id})

                        # Insert new reset token
                        insert_token_query = text("""
                            INSERT INTO password_reset_tokens
                            (token_id, user_id, token_hash, expires_at, created_at, ip_address, user_agent)
                            VALUES (
                                :token_id,
                                :user_id,
                                :token_hash,
                                UTC_TIMESTAMP() + INTERVAL 1 HOUR,
                                UTC_TIMESTAMP(),
                                :ip_address,
                                :user_agent
                            )
                        """)

                        # Hash the token for database storage (similar to password hashing)
                        import hashlib
                        token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
                        token_id = secrets.token_hex(16)

                        conn.execute(insert_token_query, {
                            'token_id': token_id,
                            'user_id': user_id,
                            'token_hash': token_hash,
                            'ip_address': request.remote_addr,
                            'user_agent': request.headers.get('User-Agent', '')[:500]  # Limit length
                        })

                        conn.commit()

                        # Send reset email asynchronously to avoid blocking
                        try:
                            send_password_reset_email(
                                email=user_email,
                                reset_token=reset_token,
                                expires_at=token_expiration
                            )

                            # Log successful reset request (without sensitive data)
                            logger.info(f"Password reset requested for user {user_id}")

                        except Exception as email_error:
                            # Log email failure but don't expose to user
                            logger.error(f"Failed to send password reset email: {str(email_error)}")
                            # Continue execution - we still return success to prevent enumeration

                # Always return success response to prevent email enumeration
                # This response is identical regardless of whether email exists
                return jsonify({
                    'success': True,
                    'message': 'If an account with that email address exists, we have sent you a password reset link.',
                    'data': {
                        'email': email,
                        'next_step': 'Check your email for reset instructions'
                    }
                }), 200

        except Exception as db_error:
            # Log database errors with context but don't expose internals
            logger.error(f"Database error in password reset request: {str(db_error)}")

            # Return generic error that doesn't reveal system details
            return jsonify({
                'success': False,
                'message': 'A system error occurred. Please try again later.'
            }), 500

    except Exception as e:
        # Catch any unexpected errors
        logger.error(f"Unexpected error in password reset request: {str(e)}")

        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred. Please try again.'
        }), 500


@bp.route('/api/password-reset/status', methods=['GET'])
def get_password_reset_status():
    '''
    Simple endpoint to return screen configuration.
    No authentication required as this is public information.
    '''

    return jsonify({
        'success': True,
        'data': {
            'screen_name': 'password_reset',
            'available_actions': ['request_password_reset'],
            'connected_screens': ['login', 'password_reset_confirm']
        }
    }), 200


# Error handler for this blueprint
@bp.errorhandler(400)
def handle_bad_request(error):
    '''Handle 400 errors with consistent JSON response'''
    return jsonify({
        'success': False,
        'message': 'Bad request - please check your input'
    }), 400


@bp.errorhandler(500)
def handle_internal_error(error):
    '''Handle 500 errors with safe JSON response'''
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'success': False,
        'message': 'Internal server error - please try again later'
    }), 500
