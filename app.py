import os

from flask import Flask, render_template, request, jsonify, redirect
from dotenv import load_dotenv

load_dotenv()

from routes.active_sessions import bp as active_sessions_bp
from routes.dashboard import bp as dashboard_bp
from routes.change_password import bp as change_password_bp
from routes.email_verification import bp as email_verification_bp
from routes.login import bp as login_bp
from routes.onboarding import bp as onboarding_bp
from routes.password_reset import bp as password_reset_bp
from routes.password_reset_confirm import bp as password_reset_confirm_bp
from routes.profile_settings import bp as profile_settings_bp
from routes.registration import bp as registration_bp
from routes.groups import bp as groups_bp
from routes.trips import bp as trips_bp
from routes.costs import bp as costs_bp

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-env")
app.register_blueprint(active_sessions_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(change_password_bp)
app.register_blueprint(email_verification_bp)
app.register_blueprint(login_bp)
app.register_blueprint(onboarding_bp)
app.register_blueprint(password_reset_bp)
app.register_blueprint(password_reset_confirm_bp)
app.register_blueprint(profile_settings_bp)
app.register_blueprint(registration_bp)
app.register_blueprint(groups_bp)
app.register_blueprint(trips_bp)
app.register_blueprint(costs_bp)


@app.route("/register", methods=["GET"])
def register():
    return render_template("registration.html")


@app.route("/registration-confirm", methods=["GET"])
def registration_confirm():
    return render_template("registration_confirm.html")


@app.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html")


@app.route("/email-verification", methods=["GET"])
def email_verification():
    return render_template("email_verification.html")


@app.route("/email-verified", methods=["GET"])
def email_verified():
    return render_template("email_verified.html")


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/active-sessions", methods=["GET"])
def active_sessions():
    return render_template("active_sessions.html")


@app.route("/password-reset-confirm", methods=["GET"])
def password_reset_confirm():
    return render_template("password_reset_confirm.html")


@app.route("/password-reset-success", methods=["GET"])
def password_reset_success():
    return render_template("password_reset_success.html")


@app.route("/onboarding", methods=["GET"])
def onboarding():
    return render_template("onboarding.html")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/create-group", methods=["GET"])
def create_group_page():
    return render_template("create_group.html")


@app.route("/invite/<token>", methods=["GET"])
def invite_group_page(token):
    return render_template("invite_join.html", invite_token=token)


@app.route("/groups/<group_id>/settings", methods=["GET"])
def group_settings_page(group_id):
    return render_template("group_settings.html", group_id=group_id)


@app.route("/groups/<group_id>/trips", methods=["GET"])
@app.route("/groups/<group_id>/costs", methods=["GET"])
@app.route("/groups/<group_id>/activity", methods=["GET"])
def group_workspace_page(group_id):
    # The workspace now lives inline on /dashboard (active group, floating tab nav).
    return redirect("/dashboard")


@app.route("/settings", methods=["GET"])
def settings():
    return render_template("settings.html")


@app.route("/faq", methods=["GET"])
def faq():
    return render_template("faq.html")


@app.route("/profile-settings", methods=["GET"])
def profile_settings():
    return render_template("profile_settings.html")


@app.route("/change-password", methods=["GET"])
def change_password():
    return render_template("change_password.html")


@app.route("/password-reset", methods=["GET", "POST"])
def password_reset():
    if request.method == "GET":
        return render_template("password_reset.html")

    return jsonify({
        "success": True,
        "message": "Als er een account bestaat met dit e-mailadres, is er een link gestuurd om het wachtwoord opnieuw in te stellen."
    }), 200


@app.route('/')
def home():
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
