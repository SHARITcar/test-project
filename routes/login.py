# ============================================
# SCREEN: login
# ============================================

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from werkzeug.security import check_password_hash
import secrets
import hashlib
import re
from datetime import datetime, timedelta
from your_db import engine
import logging

bp = Blueprint('login', __name__)

logger = logging.getLogger(__name__)


@bp.route('/api/auth/login', methods=['POST'])
def authenticate_user():
    '''
    Authenticate existing users and create secure session.
    Validates credentials, checks account status, and generates session token.

    Security measures:
    - Parameterized queries prevent SQL injection
    - Password timing attack protection via constant-time comparison
    - Account status validation prevents suspended/deleted account access
    - Email verification requirement enforces security policy
    - Secure session token generation and hashing
    '''

    # ===== INPUT VALIDATION =====
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logger.warning(f"Invalid JSON payload received: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Invalid JSON payload',
            'message': 'Request must contain valid JSON data'
        }), 400

    if not data:
        return jsonify({
            'success': False,
            'error': 'Missing request data',
            'message': 'Request body cannot be empty'
        }), 400

    # Validate required fields
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    remember_me = data.get('remember_me', False)

    validation_errors = []

    # Email validation
    if not email:
        validation_errors.append('Email is required')
    elif len(email) > 320:
        validation_errors.append('Email address too long (max 320 characters)')
    elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        validation_errors.append('Invalid email format')

    # Password validation
    if not password:
        validation_errors.append('Password is required')
    elif len(password) > 1000:  # Prevent DoS via extremely long passwords
        validation_errors.append('Password too long')

    # Remember me validation
    if not isinstance(remember_me, bool):
        validation_errors.append('Remember me must be true or false')

    if validation_errors:
        return jsonify({
            'success': False,
            'error': 'Validation failed',
            'message': 'Please correct the following errors',
            'details': validation_errors
        }), 400

    # ===== DATABASE OPERATIONS =====
    try:
        with engine.connect() as conn:
            # Fetch user data with parameterized query
            user_query = text("""
                SELECT user_id, email, password_hash, first_name, last_name,
                       avatar_url, email_verified, account_status, onboarding_completed
                FROM users
                WHERE email = :email
            """)

            result = conn.execute(user_query, {'email': email})
            user_row = result.fetchone()

            if not user_row:
                # Log failed login attempt (without revealing user doesn't exist)
                logger.warning(f"Login attempt for non-existent email: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Authentication failed',
                    'message': 'Invalid email or password'
                }), 401

            # Convert row to dict for easier access
            user = {
                'user_id': str(user_row.user_id),
                'email': user_row.email,
                'password_hash': user_row.password_hash,
                'first_name': user_row.first_name,
                'last_name': user_row.last_name,
                'avatar_url': user_row.avatar_url,
                'email_verified': user_row.email_verified,
                'account_status': user_row.account_status,
                'onboarding_completed': user_row.onboarding_completed
            }

            # ===== AUTHENTICATION CHECKS =====

            # Verify password (constant-time comparison prevents timing attacks)
            if not check_password_hash(user['password_hash'], password):
                logger.warning(f"Invalid password attempt for user: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Authentication failed',
                    'message': 'Invalid email or password'
                }), 401

            # Check account status
            if user['account_status'] != 'active':
                logger.warning(f"Login attempt for {user['account_status']} account: {email}")
                if user['account_status'] == 'suspended':
                    return jsonify({
                        'success': False,
                        'error': 'Account suspended',
                        'message': 'Your account has been suspended. Please contact support.'
                    }), 403
                elif user['account_status'] == 'deleted':
                    return jsonify({
                        'success': False,
                        'error': 'Account not found',
                        'message': 'Account not found or has been deleted.'
                    }), 404
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Account unavailable',
                        'message': 'Account is currently unavailable.'
                    }), 403

            # Check email verification
            if not user['email_verified']:
                logger.info(f"Login attempt for unverified email: {email}")
                return jsonify({
                    'success': False,
                    'error': 'Email not verified',
                    'message': 'Please verify your email address before logging in.',
                    'action_required': 'email_verification'
                }), 403

            # ===== SESSION CREATION =====

            # Generate secure session token
            session_token = secrets.token_urlsafe(32)  # 256-bit entropy
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()

            # Set session expiration based on remember_me
            if remember_me:
                expires_at = datetime.utcnow() + timedelta(days=30)
            else:
                expires_at = datetime.utcnow() + timedelta(hours=24)

            # Get client information for session tracking
            ip_address = request.environ.get(
                'HTTP_X_FORWARDED_FOR',
                request.environ.get('REMOTE_ADDR', 'unknown')
            )
            user_agent = request.headers.get('User-Agent', 'unknown')[:500]  # Truncate long user agents

            # Create session record
            session_query = text("""
                INSERT INTO user_sessions
                (session_id, user_id, token_hash, expires_at, last_seen_at,
                 created_at, ip_address, user_agent)
                VALUES
                (UUID(), :user_id, :token_hash, :expires_at, NOW(),
                 NOW(), :ip_address, :user_agent)
            """)

            conn.execute(session_query, {
                'user_id': user['user_id'],
                'token_hash': token_hash,
                'expires_at': expires_at,
                'ip_address': ip_address,
                'user_agent': user_agent
            })

            conn.commit()

            # ===== SUCCESS RESPONSE =====

            # Return minimal user data (least privilege principle)
            user_profile = {
                'user_id': user['user_id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'avatar_url': user['avatar_url'],
                'onboarding_completed': user['onboarding_completed']
            }

            logger.info(f"Successful login for user: {email}")

            return jsonify({
                'success': True,
                'message': 'Login successful',
                'data': {
                    'session_token': session_token,
                    'expires_at': expires_at.isoformat(),
                    'user': user_profile
                }
            }), 200

    except Exception as e:
        # Log the full error for debugging (without exposing to client)
        logger.error(f"Database error during authentication for {email}: {str(e)}")

        # Return generic error to prevent information leakage
        return jsonify({
            'success': False,
            'error': 'Authentication service unavailable',
            'message': 'Unable to process login request. Please try again later.'
        }), 500


# ===== SECURITY DOCUMENTATION =====
"""
SECURITY MEASURES IMPLEMENTED:

1. INPUT VALIDATION:
   - JSON payload validation prevents malformed requests
   - Email format validation with length limits prevents injection
   - Password length limits prevent DoS attacks
   - Type checking on remember_me prevents unexpected values

2. SQL INJECTION PREVENTION:
   - All queries use parameterized statements with :placeholder syntax
   - No string interpolation or concatenation in SQL queries

3. AUTHENTICATION SECURITY:
   - Constant-time password verification prevents timing attacks
   - Generic error messages prevent user enumeration
   - Account status validation prevents suspended/deleted account access
   - Email verification requirement enforces security policy

4. SESSION SECURITY:
   - Cryptographically secure token generation (256-bit entropy)
   - Token hashing before storage prevents token theft from DB
   - Session expiration with different durations for remember_me
   - IP and User-Agent tracking for session monitoring

5. ERROR HANDLING:
   - Detailed logging for debugging without exposing internals
   - Generic error messages prevent information disclosure
   - Proper HTTP status codes for different error conditions
   - Graceful handling of database connection failures

6. DATA MINIMIZATION:
   - Only returns essential user profile data
   - Excludes sensitive fields like password_hash from responses
   - Limits user_agent length to prevent storage attacks

RECOMMENDED ADDITIONS FOR PRODUCTION:
- Rate limiting on login endpoint (e.g., 5 attempts per IP per minute)
- CSRF protection for state-changing operations
- Account lockout after repeated failed attempts
- Session cleanup background job for expired sessions
- Audit logging for security events
- Two-factor authentication support
"""
