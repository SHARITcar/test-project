import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask


def _make_supabase_client_module():
    mod = types.ModuleType("supabase_client")
    mod.supabase = MagicMock()
    mod.get_user_from_token = MagicMock(return_value=None)
    mod.db_for = MagicMock(return_value=MagicMock())
    mod.get_token_from_request = MagicMock(return_value=None)
    return mod


class LoginRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.login", None)
        cls.login_module = importlib.import_module("routes.login")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.login_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _mock_successful_login(self, user_id="user-123", email="test@example.com"):
        mock_user = SimpleNamespace(id=user_id, email=email)
        mock_session = SimpleNamespace(
            access_token="test-access-token",
            refresh_token="test-refresh-token",
            expires_at=9999999999,
        )
        mock_response = SimpleNamespace(user=mock_user, session=mock_session)
        self.fake_sc.supabase.auth.sign_in_with_password.return_value = mock_response

        mock_profile_result = MagicMock()
        mock_profile_result.data = {
            "first_name": "Test",
            "last_name": "User",
            "avatar_url": None,
            "onboarding_completed": True,
            "account_status": "active",
        }
        db_client = MagicMock()
        db_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_profile_result
        self.fake_sc.db_for.return_value = db_client

    def test_login_success(self):
        self._mock_successful_login()
        response = self.client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"]["access_token"], "test-access-token")
        self.assertEqual(payload["data"]["user"]["email"], "test@example.com")

    def test_login_invalid_credentials(self):
        self.fake_sc.supabase.auth.sign_in_with_password.side_effect = Exception(
            "Invalid login credentials"
        )
        response = self.client.post(
            "/api/auth/login",
            json={"email": "test@example.com", "password": "wrong-password"},
        )
        self.assertEqual(response.status_code, 401)
        payload = response.get_json()
        self.assertFalse(payload["success"])
        self.assertIn("Invalid email or password", payload["error"])

    def test_login_missing_fields(self):
        response = self.client.post(
            "/api/auth/login",
            json={"email": "", "password": ""},
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["success"])

    def test_login_email_not_confirmed(self):
        self.fake_sc.supabase.auth.sign_in_with_password.side_effect = Exception(
            "Email not confirmed"
        )
        response = self.client.post(
            "/api/auth/login",
            json={"email": "unverified@example.com", "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 403)
        payload = response.get_json()
        self.assertFalse(payload["success"])
        self.assertEqual(payload.get("action_required"), "email_verification")


if __name__ == "__main__":
    unittest.main()
