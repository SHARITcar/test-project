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


class RegistrationRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.registration", None)
        cls.registration_module = importlib.import_module("routes.registration")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        app = Flask(__name__)
        app.register_blueprint(self.registration_module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_register_user_success(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.supabase.auth.sign_up.return_value = SimpleNamespace(user=mock_user)

        response = self.client.post(
            "/api/register_user",
            json={
                "email": "test@example.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Account created", response.get_json()["message"])

    def test_register_user_duplicate_email(self):
        self.fake_sc.supabase.auth.sign_up.side_effect = Exception(
            "User already registered"
        )
        response = self.client.post(
            "/api/register_user",
            json={
                "email": "existing@example.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "Email already registered")

    def test_register_user_rejects_non_json(self):
        response = self.client.post(
            "/api/register_user",
            data={"email": "test@example.com", "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Content-Type must be application/json")

    def test_register_user_rejects_weak_password(self):
        response = self.client.post(
            "/api/register_user",
            json={
                "email": "test@example.com",
                "password": "weakpassword",
                "confirm_password": "weakpassword",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("uppercase", response.get_json()["error"])

    def test_register_user_passwords_do_not_match(self):
        response = self.client.post(
            "/api/register_user",
            json={
                "email": "test@example.com",
                "password": "Password123!",
                "confirm_password": "Different123!",
                "first_name": "Test",
                "last_name": "User",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("match", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
