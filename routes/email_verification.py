# ============================================
# SCREEN: email_verification
# ============================================
# Supabase Auth handles email verification automatically on sign_up.
# The verification email is sent by Supabase (configurable in the dashboard).
# After clicking the link, Supabase processes the token and redirects to
# APP_BASE_URL/email-verified with session tokens in the URL hash fragment.
# ============================================

from flask import Blueprint, redirect, request, jsonify

bp = Blueprint("email_verification", __name__)


@bp.route("/verify-email", methods=["GET"])
def verify_email_from_link():
    """
    Landing route for Supabase email verification redirect.
    Supabase appends tokens to the hash fragment (#access_token=...&type=signup).
    JavaScript on the target page handles the token exchange.
    """
    error = request.args.get("error")
    if error:
        return redirect(f"/email-verification?error={error}")
    return redirect("/email-verified")


@bp.route("/api/verification_email_preview", methods=["POST"])
def verification_email_preview():
    """
    Return the Dutch verification email content for previewing
    custom email templates (e.g. for Supabase SMTP hook configuration).
    """
    data = request.get_json() or {}
    first_name = (data.get("first_name") or "gebruiker").strip()
    verification_url = data.get("verification_url") or "https://example.com/verify"

    subject = "Bevestig je e-mailadres voor SHARIT"
    body = (
        f"Hi {first_name},\n\n"
        "Welkom bij SHARIT, de eerste stap in gemakkelijk je auto delen.\n"
        "Om je account te activeren, bevestig je hieronder je e-mailadres.\n"
        f"{verification_url}\n\n"
        "Heb je geen account aangemaakt? Dan kun je deze mail negeren.\n\n"
        "Gedeelde groet,\n"
        "Team SHARIT"
    )

    return jsonify({"subject": subject, "body": body}), 200
