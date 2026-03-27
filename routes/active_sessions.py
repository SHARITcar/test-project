from flask import Blueprint, request, jsonify
from sqlalchemy import text
from your_db import engine  # replace with your real DB import

bp = Blueprint("active_sessions", __name__)

@bp.route("/api/demo/register_user", methods=["POST"])
def register_user():
    email = request.json.get("email")
    password = request.json.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    query = text("""
        INSERT INTO users (email, password_hash, email_verified)
        VALUES (:email, :password_hash, false)
    """)

    with engine.begin() as conn:
        conn.execute(query, {"email": email, "password_hash": password})

    return jsonify({
        "message": "User account created successfully. Please verify your email address."
    }), 201


@bp.route("/api/demo/verify_email", methods=["POST"])
def verify_email():
    token = request.json.get("token")

    if not token:
        return jsonify({"error": "Verification token is required"}), 400

    query = text("""
        UPDATE users
        SET email_verified = true
        WHERE verification_token = :token
    """)

    with engine.begin() as conn:
        result = conn.execute(query, {"token": token})

    if result.rowcount == 0:
        return jsonify({"error": "Invalid or expired verification token"}), 404

    return jsonify({
        "message": "Email verified successfully. Redirecting to onboarding."
    }), 200
