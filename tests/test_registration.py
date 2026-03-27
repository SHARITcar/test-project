import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask


class RegistrationRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine

        sys.modules["your_db"] = fake_db_module
        cls.registration_module = importlib.import_module("routes.registration")

    def setUp(self):
        self.mock_engine.reset_mock()
        app = Flask(__name__)
        app.register_blueprint(self.registration_module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_register_user_success(self):
        connection = MagicMock()
        connection.execute.side_effect = [MagicMock(first=MagicMock(return_value=None)), MagicMock()]
        self.mock_engine.begin.return_value.__enter__.return_value = connection

        with patch.object(self.registration_module, "send_verification_email", return_value={"subject": "x", "body": "y"}):
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
        self.assertEqual(
            response.get_json()["message"],
            "User account created successfully. Please verify your email address.",
        )

    def test_register_user_duplicate_email(self):
        existing_user_result = MagicMock()
        existing_user_result.first.return_value = object()

        connection = MagicMock()
        connection.execute.return_value = existing_user_result
        self.mock_engine.begin.return_value.__enter__.return_value = connection

        with patch.object(self.registration_module, "send_verification_email", return_value={"subject": "x", "body": "y"}):
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

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "Email already registered")

    def test_register_user_rejects_non_json(self):
        response = self.client.post(
            "/api/register_user",
            data={
                "email": "test@example.com",
                "password": "Password123!",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Content-Type must be application/json")

    def test_register_user_rejects_weak_password(self):
        response = self.client.post(
            "/api/register_user",
            json={
                "email": "test@example.com",
                "password": "kakakakaka",
                "confirm_password": "kakakakaka",
                "first_name": "Test",
                "last_name": "User",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("uppercase", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
