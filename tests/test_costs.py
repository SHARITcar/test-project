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


class CostsRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.costs", None)
        cls.costs_module = importlib.import_module("routes.costs")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.costs_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123", email="test@example.com"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(id=user_id, email=email)

    def test_list_costs_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.get("/api/groups/group-123/costs")
        self.assertEqual(response.status_code, 401)

    def test_list_costs_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),
            _mock_table([
                {"id": "cost-1", "category": "Insurance", "paid_by": "user-123", "amount": 62.40,
                 "cost_date": "2026-06-05", "notes": "Full tank", "logged_by": "user-123", "created_at": "2026-06-05T10:00:00Z"},
            ]),
            _mock_table([{"id": "user-123", "first_name": "Floortje", "last_name": ""}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/costs",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["costs"]), 1)
        self.assertEqual(payload["costs"][0]["paidByName"], "Floortje")
        self.assertEqual(payload["summary"]["total"], 62.40)

    def test_create_cost_validation_error(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/groups/group-123/costs",
            json={"category": "Snacks", "paidBy": "", "amount": -5},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        errors = response.get_json()["fieldErrors"]
        self.assertIn("category", errors)
        self.assertIn("paidBy", errors)
        self.assertIn("amount", errors)

    def test_create_cost_rejects_non_member_payer(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            json={"category": "Insurance", "paidBy": "user-999", "amount": 20},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("paidBy", response.get_json()["fieldErrors"])

    def test_create_cost_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
            _mock_table([{"id": "cost-1", "category": "Insurance", "paid_by": "user-123", "amount": 62.40}]),  # insert
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            json={"category": "Insurance", "paidBy": "user-123", "amount": 62.40, "costDate": "2026-06-05", "notes": "Full tank"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["cost"]["amount"], 62.40)

    def test_get_balances_fixed_costs_equal_split_and_trip_debt(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-a"}, {"user_id": "user-b"}]),  # group members
            _mock_table([{"id": "user-a", "first_name": "Ada", "last_name": ""}, {"id": "user-b", "first_name": "Bo", "last_name": ""}]),  # profiles
            _mock_table([{"id": "trip-1", "odometer_reading": 100, "distance_km": 100, "cost": 50,
                          "notes": None, "trip_date": "2026-06-01", "logged_by": "user-a", "created_at": "2026-06-01T00:00:00Z"}]),  # trips
            _mock_table([{"trip_id": "trip-1", "user_id": "user-a"}]),  # trip_participants (solo trip by user-a)
            _mock_table([{"id": "cost-1", "category": "Insurance", "paid_by": "user-b", "amount": 100,
                          "cost_date": "2026-06-01", "notes": None, "created_at": "2026-06-01T00:00:00Z"}]),  # costs
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/balances",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        balances = {b["userId"]: b["balance"] for b in payload["balances"]}
        # Fixed cost (100) splits equally: 50 each. user-a also owes their trip's full
        # cost (50, solo participant) as unreconciled fuel-usage debt.
        self.assertEqual(balances["user-a"], -100.0)
        self.assertEqual(balances["user-b"], 50.0)
        self.assertEqual(len(payload["activity"]), 2)
        trip_entry = next(entry for entry in payload["activity"] if entry["type"] == "trip")
        self.assertEqual(trip_entry["amount"], 50)


if __name__ == "__main__":
    unittest.main()
