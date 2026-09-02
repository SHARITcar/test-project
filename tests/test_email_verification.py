import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock

from flask import Flask


def _make_supabase_client_module():
    mod = types.ModuleType("supabase_client")
    mod.supabase = MagicMock()
    mod.get_user_from_token = MagicMock(return_value=None)
    mod.db_for = MagicMock(return_value=MagicMock())
    mod.get_token_from_request = MagicMock(return_value=None)
    return mod


class EmailVerificationRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.email_verification", None)
        cls.module = importlib.import_module("routes.email_verification")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        app = Flask(__name__)
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_preview_uses_expected_copy(self):
        response = self.client.post(
            "/api/verification_email_preview",
            json={"first_name": "Voornaam", "email": "test@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["subject"], "Bevestig je e-mailadres voor SHARIT")
        self.assertIn("Hi Voornaam,", payload["body"])
        self.assertIn("Welkom bij SHARIT", payload["body"])

    def test_verify_email_link_redirects_to_verified(self):
        response = self.client.get("/verify-email", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/email-verified", response.headers["Location"])

    def test_verify_email_link_with_error_redirects_to_verification_page(self):
        response = self.client.get(
            "/verify-email?error=access_denied", follow_redirects=False
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/email-verification", response.headers["Location"])

    def test_resend_verification_email_success(self):
        self.fake_sc.supabase.auth.resend.return_value = MagicMock()
        response = self.client.post(
            "/api/resend_verification_email",
            json={"email": "test@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("verstuurd", response.get_json()["message"])

    def test_resend_verification_email_missing_email(self):
        response = self.client.post(
            "/api/resend_verification_email",
            json={},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("E-mailadres is verplicht", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
