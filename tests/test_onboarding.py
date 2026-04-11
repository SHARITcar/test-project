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


class OnboardingRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.onboarding", None)
        cls.onboarding_module = importlib.import_module("routes.onboarding")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.onboarding_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123", email="test@example.com"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(
            id=user_id, email=email
        )

    def test_complete_onboarding_success(self):
        self._setup_valid_session()
        mock_result = MagicMock()
        mock_result.data = [
            {
                "first_name": "Test",
                "last_name": "User",
                "avatar_url": None,
                "onboarding_completed": True,
            }
        ]
        db_client = MagicMock()
        db_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_result
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/complete_onboarding",
            json={},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Onboarding completed", response.get_json()["message"])

    def test_complete_onboarding_with_avatar(self):
        self._setup_valid_session()
        mock_result = MagicMock()
        mock_result.data = [
            {
                "first_name": "Test",
                "last_name": "User",
                "avatar_url": "https://example.com/avatar.jpg",
                "onboarding_completed": True,
            }
        ]
        db_client = MagicMock()
        db_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_result
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/complete_onboarding",
            json={"avatar_url": "https://example.com/avatar.jpg"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        # Verify avatar_url was included in the update payload
        update_call = db_client.table.return_value.update.call_args
        self.assertIn("avatar_url", update_call.args[0])

    def test_complete_onboarding_no_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.post("/api/complete_onboarding", json={})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
