import sys
import types
import importlib
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


def _mock_table(result_data):
    table = MagicMock()
    for method_name in ["select", "eq", "single", "limit", "order", "in_", "insert", "update", "delete"]:
        getattr(table, method_name).return_value = table
    table.execute.return_value = SimpleNamespace(data=result_data)
    return table


class MarkTipSeenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.profile_settings", None)
        cls.module = importlib.import_module("routes.profile_settings")

    def setUp(self):
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(id=user_id, email="test@example.com")

    def test_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.post("/api/profile/tips-seen", json={"tip": "trips_tip"})
        self.assertEqual(response.status_code, 401)

    def test_rejects_unknown_tip(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/profile/tips-seen",
            json={"tip": "not_a_real_tip"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_marks_tip_seen(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table({"seen_tips": []}),
            _mock_table([{"id": "user-123"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/profile/tips-seen",
            json={"tip": "trips_tip"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["seen_tips"], ["trips_tip"])

    def test_idempotent_when_already_seen(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table({"seen_tips": ["trips_tip"]}),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/profile/tips-seen",
            json={"tip": "trips_tip"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["seen_tips"], ["trips_tip"])
        db_client.table.assert_called_once()


if __name__ == "__main__":
    unittest.main()
