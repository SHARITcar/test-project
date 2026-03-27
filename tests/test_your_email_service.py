import os
import unittest
from datetime import datetime
from unittest.mock import patch

import your_email_service


class EmailServiceTests(unittest.TestCase):
    def test_send_password_reset_email_uses_smtp(self):
        with patch.dict(
            os.environ,
            {
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
            with patch.object(your_email_service.smtplib, "SMTP") as mock_smtp:
                your_email_service.send_password_reset_email(
                    email="test@example.com",
                    reset_token="reset-token",
                    expires_at=datetime(2025, 2, 24, 12, 0, 0),
                )

        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        smtp_client = mock_smtp.return_value.__enter__.return_value
        smtp_client.starttls.assert_called_once()
        smtp_client.login.assert_called_once_with("info@sharit.me", "secret")
        smtp_client.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
