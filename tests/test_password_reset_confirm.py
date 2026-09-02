import importlib
import os
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


class PasswordResetConfirmRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.password_reset_confirm", None)
        cls.module = importlib.import_module("routes.password_reset_confirm")

    def setUp(self):
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        app = Flask(__name__)
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def _valid_payload(self, password="Password123!"):
        return {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "new_password": password,
        }

    def test_reset_password_success(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user

        mock_client = MagicMock()
        fake_env = {"SUPABASE_URL": "https://fake.supabase.co", "SUPABASE_ANON_KEY": "fake-key"}
        with patch.dict(os.environ, fake_env):
            with patch.object(self.module, "create_client", return_value=mock_client):
                response = self.client.post(
                    "/api/password-reset/confirm",
                    json=self._valid_payload(),
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        mock_client.auth.set_session.assert_called_once_with(
            "test-access-token", "test-refresh-token"
        )
        mock_client.auth.update_user.assert_called_once_with(
            {"password": "Password123!"}
        )

    def test_reset_password_missing_tokens(self):
        response = self.client.post(
            "/api/password-reset/confirm",
            json={"new_password": "Password123!"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("access_token", response.get_json()["error"])

    def test_reset_password_invalid_token(self):
        self.fake_sc.get_user_from_token.return_value = None
        response = self.client.post(
            "/api/password-reset/confirm",
            json=self._valid_payload(),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Ongeldige of verlopen", response.get_json()["error"])

    def test_reset_password_weak_password(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user
        response = self.client.post(
            "/api/password-reset/confirm",
            json=self._valid_payload(password="weak"),
        )
        self.assertEqual(response.status_code, 400)

    def test_reset_password_requires_json(self):
        response = self.client.post(
            "/api/password-reset/confirm",
            data={"access_token": "x", "new_password": "Password123!"},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
