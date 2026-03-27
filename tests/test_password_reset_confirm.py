import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask


class PasswordResetConfirmRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine
        sys.modules["your_db"] = fake_db_module
        cls.module = importlib.import_module("routes.password_reset_confirm")

    def setUp(self):
        self.mock_engine.reset_mock()
        app = Flask(__name__)
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_reset_password_sends_confirmation_email(self):
        connection = MagicMock()
        connection.execute.side_effect = [
            MagicMock(mappings=MagicMock(return_value=MagicMock(first=MagicMock(return_value={
                "token_id": "token-123",
                "user_id": "user-123",
            })))),
            MagicMock(mappings=MagicMock(return_value=MagicMock(first=MagicMock(return_value={
                "email": "test@example.com",
            })))),
            MagicMock(),
            MagicMock(),
        ]
        self.mock_engine.begin.return_value.__enter__.return_value = connection

        with patch.object(self.module, "send_password_changed_email") as mock_send_email:
            response = self.client.post(
                "/api/password-reset/confirm",
                json={
                    "reset_token": "plain-reset-token",
                    "new_password": "Password123!",
                },
            )

        self.assertEqual(response.status_code, 200)
        mock_send_email.assert_called_once()


if __name__ == "__main__":
    unittest.main()
