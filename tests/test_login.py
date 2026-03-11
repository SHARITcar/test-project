import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from flask import Flask


class LoginRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine

        cls.db_patch = patch.dict(sys.modules, {"your_db": fake_db_module})
        cls.db_patch.start()
        cls.login_module = importlib.import_module("routes.login")

    @classmethod
    def tearDownClass(cls):
        cls.db_patch.stop()

    def setUp(self):
        self.mock_engine.reset_mock()
        app = Flask(__name__)
        app.register_blueprint(self.login_module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_login_success(self):
        row = SimpleNamespace(
            user_id=123,
            email="test@example.com",
            password_hash="stored-hash",
            first_name="Test",
            last_name="User",
            avatar_url=None,
            email_verified=True,
            account_status="active",
            onboarding_completed=True,
        )

        conn = MagicMock()
        user_result = MagicMock()
        user_result.fetchone.return_value = row

        conn.execute.side_effect = [user_result, MagicMock()]
        self.mock_engine.connect.return_value.__enter__.return_value = conn

        with patch.object(self.login_module.secrets, "token_urlsafe", return_value="plain_session_token"):
            with patch.object(self.login_module, "check_password_hash", return_value=True):
                response = self.client.post(
                    "/api/auth/login",
                    json={"email": "test@example.com", "password": "Password123!", "remember_me": False},
                )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"]["session_token"], "plain_session_token")
        self.assertEqual(payload["data"]["user"]["email"], "test@example.com")
        conn.commit.assert_called_once()

    def test_login_invalid_password(self):
        row = SimpleNamespace(
            user_id=123,
            email="test@example.com",
            password_hash="stored-hash",
            first_name="Test",
            last_name="User",
            avatar_url=None,
            email_verified=True,
            account_status="active",
            onboarding_completed=True,
        )

        conn = MagicMock()
        user_result = MagicMock()
        user_result.fetchone.return_value = row

        conn.execute.return_value = user_result
        self.mock_engine.connect.return_value.__enter__.return_value = conn

        with patch.object(self.login_module, "check_password_hash", return_value=False):
            response = self.client.post(
                "/api/auth/login",
                json={"email": "test@example.com", "password": "wrong-password", "remember_me": False},
            )

        self.assertEqual(response.status_code, 401)
        payload = response.get_json()
        self.assertFalse(payload["success"])
        self.assertEqual(payload["error"], "Authentication failed")
        conn.commit.assert_not_called()

    def test_login_validation_error(self):
        response = self.client.post(
            "/api/auth/login",
            json={"email": "not-an-email", "password": "", "remember_me": "yes"},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["success"])
        self.assertEqual(payload["error"], "Validation failed")


if __name__ == "__main__":
    unittest.main()
