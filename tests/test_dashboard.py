import importlib
import sys
import types
import unittest
from hashlib import sha256
from unittest.mock import MagicMock

from flask import Flask


class DashboardRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine
        sys.modules["your_db"] = fake_db_module
        cls.dashboard_module = importlib.import_module("routes.dashboard")

    def setUp(self):
        self.mock_engine.reset_mock()
        app = Flask(__name__)
        app.register_blueprint(self.dashboard_module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_get_user_profile_hashes_bearer_token(self):
        connection = MagicMock()
        connection.execute.return_value.mappings.return_value.first.return_value = {
            "user_id": "123",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "avatar_url": None,
            "created_at": "2024-01-01",
        }
        self.mock_engine.connect.return_value.__enter__.return_value = connection

        response = self.client.get(
            "/api/get_user_profile",
            headers={"Authorization": "Bearer plain_session_token"},
        )

        self.assertEqual(response.status_code, 200)
        connection.execute.assert_called_once()
        params = connection.execute.call_args.args[1]
        self.assertEqual(
            params["token"],
            sha256("plain_session_token".encode()).hexdigest(),
        )

    def test_logout_hashes_bearer_token(self):
        connection = MagicMock()
        self.mock_engine.begin.return_value.__enter__.return_value = connection

        response = self.client.post(
            "/api/logout_user",
            headers={"Authorization": "Bearer plain_session_token"},
        )

        self.assertEqual(response.status_code, 200)
        connection.execute.assert_called_once()
        params = connection.execute.call_args.args[1]
        self.assertEqual(
            params["token"],
            sha256("plain_session_token".encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
