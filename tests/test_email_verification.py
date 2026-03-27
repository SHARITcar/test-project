import importlib
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask


class EmailVerificationRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mock_engine = MagicMock()
        fake_db_module = types.ModuleType("your_db")
        fake_db_module.engine = cls.mock_engine
        sys.modules["your_db"] = fake_db_module
        cls.module = importlib.import_module("routes.email_verification")
        cls.module = importlib.reload(cls.module)

    def setUp(self):
        self.mock_engine.reset_mock()
        os.environ["SECRET_KEY"] = "test-secret"
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "test-secret"
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def test_preview_uses_expected_copy(self):
        response = self.client.post(
            "/api/verification_email_preview",
            json={"first_name": "Voornaam", "email": "test@example.com"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["subject"], "Bevestig je e-mailadres voor SHARIT")
        self.assertIn("Hi Voornaam,", payload["body"])
        self.assertIn("Welkom bij SHARIT", payload["body"])

    def test_verify_email_api_marks_user_verified(self):
        token = self.module.generate_verification_token("test@example.com")
        connection = MagicMock()
        connection.execute.return_value = MagicMock(rowcount=1)
        self.mock_engine.begin.return_value.__enter__.return_value = connection

        response = self.client.post(
            "/api/verify_email",
            json={"verification_token": token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Verification success", response.get_json()["message"])

    def test_send_verification_email_uses_smtp(self):
        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "test-secret",
                "APP_BASE_URL": "http://localhost:5000",
                "MAIL_HOST": "smtp.example.com",
                "MAIL_PORT": "587",
                "MAIL_USERNAME": "info@sharit.me",
                "MAIL_PASSWORD": "secret",
                "MAIL_USE_TLS": "true",
                "MAIL_USE_SSL": "false",
                "MAIL_VERIFY_CERT": "false",
                "MAIL_FROM": "info@sharit.me",
            },
            clear=False,
        ):
            with patch.object(self.module.smtplib, "SMTP") as mock_smtp:
                self.module.send_verification_email("test@example.com", "Voornaam")

        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        smtp_client = mock_smtp.return_value.__enter__.return_value
        smtp_client.starttls.assert_called_once()
        smtp_client.login.assert_called_once_with("info@sharit.me", "secret")
        smtp_client.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
