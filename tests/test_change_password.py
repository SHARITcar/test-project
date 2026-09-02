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
    mod.get_token_from_request = MagicMock(return_value="original-access-token")
    return mod


class ChangePasswordRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.change_password", None)
        cls.module = importlib.import_module("routes.change_password")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.return_value = "original-access-token"
        app = Flask(__name__)
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def _valid_payload(self):
        return {
            "current_password": "OldPassword1!",
            "new_password": "NewPassword1!",
            "confirm_password": "NewPassword1!",
            "refresh_token": "original-refresh-token",
        }

    def _post(self, payload):
        return self.client.post(
            "/api/change_password",
            json=payload,
            headers={"Authorization": "Bearer original-access-token"},
        )

    def test_change_password_success_uses_callers_own_session(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user

        # The re-verification login creates its own, separate session --
        # this must NOT be the one used to perform the update.
        verify_session = SimpleNamespace(access_token="verify-access-token", refresh_token="verify-refresh-token")
        self.fake_sc.supabase.auth.sign_in_with_password.return_value = SimpleNamespace(
            user=mock_user, session=verify_session
        )

        mock_client = MagicMock()
        fake_env = {"SUPABASE_URL": "https://fake.supabase.co", "SUPABASE_ANON_KEY": "fake-key"}
        with patch.dict(os.environ, fake_env):
            with patch.object(self.module, "create_client", return_value=mock_client):
                response = self._post(self._valid_payload())

        self.assertEqual(response.status_code, 200)
        # The update must run on the CALLER's original tokens, not the
        # throwaway verification session -- otherwise Supabase revokes the
        # browser's real session instead of the verification one.
        mock_client.auth.set_session.assert_called_once_with(
            "original-access-token", "original-refresh-token"
        )
        mock_client.auth.update_user.assert_called_once_with({"password": "NewPassword1!"})

    def test_change_password_requires_refresh_token(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user

        payload = self._valid_payload()
        del payload["refresh_token"]
        response = self._post(payload)

        self.assertEqual(response.status_code, 400)

    def test_change_password_wrong_current_password(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user
        self.fake_sc.supabase.auth.sign_in_with_password.side_effect = Exception(
            "Invalid login credentials"
        )

        response = self._post(self._valid_payload())

        self.assertEqual(response.status_code, 400)
        self.assertIn("incorrect", response.get_json()["error"].lower())

    def test_change_password_mismatched_confirmation(self):
        mock_user = SimpleNamespace(id="user-123", email="test@example.com")
        self.fake_sc.get_user_from_token.return_value = mock_user

        payload = self._valid_payload()
        payload["confirm_password"] = "SomethingElse1!"
        response = self._post(payload)

        self.assertEqual(response.status_code, 400)

    def test_change_password_requires_auth(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.post("/api/change_password", json=self._valid_payload())
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
