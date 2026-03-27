import importlib
import sys
import types
import unittest
from hashlib import sha256
from unittest.mock import MagicMock

from flask import Flask


class OnboardingRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine
        sys.modules["your_db"] = fake_db_module
        cls.onboarding_module = importlib.import_module("routes.onboarding")

    def setUp(self):
        self.mock_engine.reset_mock()
        app = Flask(__name__)
        app.register_blueprint(self.onboarding_module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_complete_onboarding_uses_session_token(self):
        session_connection = MagicMock()
        session_connection.execute.return_value.mappings.return_value.first.return_value = {
            "user_id": "user-123"
        }
        self.mock_engine.connect.return_value.__enter__.return_value = session_connection

        transaction_connection = MagicMock()
        transaction_connection.execute.side_effect = [
            MagicMock(),
            MagicMock(mappings=MagicMock(return_value=MagicMock(first=MagicMock(return_value={
                "user_id": "user-123",
                "email": "test@example.com",
                "first_name": "Test",
                "last_name": "User",
                "avatar_url": None,
                "onboarding_completed": True,
            }))))
        ]
        self.mock_engine.begin.return_value.__enter__.return_value = transaction_connection

        response = self.client.post(
            "/api/complete_onboarding",
            json={},
            headers={"Authorization": "Bearer plain_session_token"},
        )

        self.assertEqual(response.status_code, 200)
        session_params = session_connection.execute.call_args.args[1]
        self.assertEqual(
            session_params["token_hash"],
            sha256("plain_session_token".encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
