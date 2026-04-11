import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from flask import Flask


def _make_supabase_client_module():
    mod = types.ModuleType("supabase_client")
    mod.supabase = MagicMock()
    mod.get_user_from_token = MagicMock(return_value=None)
    mod.db_for = MagicMock(return_value=MagicMock())
    mod.get_token_from_request = MagicMock(return_value=None)
    return mod


class DashboardRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.dashboard", None)
        cls.dashboard_module = importlib.import_module("routes.dashboard")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.dashboard_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123", email="test@example.com"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(
            id=user_id, email=email
        )

    def test_get_user_profile_success(self):
        self._setup_valid_session()
        mock_result = MagicMock()
        mock_result.data = {
            "first_name": "Test",
            "last_name": "User",
            "avatar_url": None,
            "onboarding_completed": True,
            "created_at": "2024-01-01",
        }
        db_client = MagicMock()
        db_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_result
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/get_user_profile",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("user_profile", payload)
        self.assertEqual(payload["user_profile"]["email"], "test@example.com")

    def test_get_user_profile_no_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.get("/api/get_user_profile")
        self.assertEqual(response.status_code, 401)

    def test_get_user_profile_invalid_token(self):
        self.fake_sc.get_token_from_request.return_value = "bad-token"
        self.fake_sc.get_user_from_token.return_value = None
        response = self.client.get(
            "/api/get_user_profile",
            headers={"Authorization": "Bearer bad-token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_logout_success(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/logout_user",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Logout successful", response.get_json()["message"])

    def test_logout_no_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.post("/api/logout_user")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
