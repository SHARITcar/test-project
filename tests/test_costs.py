import io
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
                {"id": "cost-1", "category": "Car insurance", "paid_by": "user-123", "amount": 62.40,
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
            json={"category": "Car insurance", "paidBy": "user-999", "amount": 20},
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
            _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-123", "amount": 62.40}]),  # insert
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            json={"category": "Car insurance", "paidBy": "user-123", "amount": 62.40, "costDate": "2026-06-05", "notes": "Full tank"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["cost"]["amount"], 62.40)

    def test_create_cost_defaults_participants_to_current_members(self):
        self._setup_valid_session()
        db_client = MagicMock()
        insert_table = _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-123", "amount": 62.40}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}, {"user_id": "user-456"}]),  # group members
            insert_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            json={"category": "Car insurance", "paidBy": "user-123", "amount": 62.40},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 201)
        insert_table.insert.assert_called_once()
        inserted = insert_table.insert.call_args[0][0]
        self.assertEqual(sorted(inserted["participants"]), ["user-123", "user-456"])
        self.assertEqual(inserted["allocation_method"], "equal")

    def test_create_cost_accepts_explicit_participants_and_allocation_method(self):
        self._setup_valid_session()
        db_client = MagicMock()
        insert_table = _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-123", "amount": 62.40}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}, {"user_id": "user-456"}]),  # group members
            insert_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            json={
                "category": "Car insurance",
                "paidBy": "user-123",
                "amount": 62.40,
                "participantIds": ["user-123"],
                "allocationMethod": "per_km",
            },
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 201)
        inserted = insert_table.insert.call_args[0][0]
        self.assertEqual(inserted["participants"], ["user-123"])
        self.assertEqual(inserted["allocation_method"], "per_km")

    def test_get_balances_fixed_costs_equal_split_and_trip_debt(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-a"}, {"user_id": "user-b"}]),  # group members
            _mock_table([{"id": "user-a", "first_name": "Ada", "last_name": ""}, {"id": "user-b", "first_name": "Bo", "last_name": ""}]),  # profiles
            _mock_table([{"id": "trip-1", "odometer_start": 0, "odometer_end": 100, "distance_km": 100, "cost": 50,
                          "notes": None, "trip_date": "2026-06-01", "logged_by": "user-a", "created_at": "2026-06-01T00:00:00Z"}]),  # trips
            _mock_table([{"trip_id": "trip-1", "user_id": "user-a"}]),  # trip_participants (solo trip by user-a)
            _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-b", "amount": 100,
                          "cost_date": "2026-06-01", "notes": None, "participants": None,
                          "allocation_method": None, "created_at": "2026-06-01T00:00:00Z"}]),  # costs
            _mock_table([{"price_per_km": 0.29}]),  # group price_per_km
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/balances",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        balances = {b["userId"]: b["balance"] for b in payload["balances"]}
        # No participant snapshot on this (legacy) cost row -> falls back to an equal
        # split across today's members: 50 each. user-a also owes their trip's full
        # cost (50, solo participant) as unreconciled fuel-usage debt.
        self.assertEqual(balances["user-a"], -100.0)
        self.assertEqual(balances["user-b"], 50.0)
        self.assertEqual(len(payload["activity"]), 2)
        trip_entry = next(entry for entry in payload["activity"] if entry["type"] == "trip")
        self.assertEqual(trip_entry["amount"], 50)

        all_time = payload["summary"]["allTime"]
        self.assertEqual(all_time["kmDriven"], 100.0)
        self.assertEqual(all_time["flexibleCosts"], 50.0)
        self.assertEqual(all_time["fixedCosts"], 100.0)
        self.assertEqual(all_time["pricePerKm"], 0.29)

    def test_get_balances_per_km_allocation_weights_by_distance(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-a"}, {"user_id": "user-b"}]),  # group members
            _mock_table([{"id": "user-a", "first_name": "Ada", "last_name": ""}, {"id": "user-b", "first_name": "Bo", "last_name": ""}]),  # profiles
            _mock_table([
                {"id": "trip-1", "odometer_start": 0, "odometer_end": 80, "distance_km": 80, "cost": None,
                 "notes": None, "trip_date": "2026-06-01", "logged_by": "user-a", "created_at": "2026-06-01T00:00:00Z"},
                {"id": "trip-2", "odometer_start": 0, "odometer_end": 20, "distance_km": 20, "cost": None,
                 "notes": None, "trip_date": "2026-06-01", "logged_by": "user-b", "created_at": "2026-06-01T00:00:00Z"},
            ]),  # trips
            _mock_table([
                {"trip_id": "trip-1", "user_id": "user-a"},
                {"trip_id": "trip-2", "user_id": "user-b"},
            ]),  # trip_participants
            _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-a", "amount": 100,
                          "cost_date": "2026-06-01", "notes": None, "participants": ["user-a", "user-b"],
                          "allocation_method": "per_km", "created_at": "2026-06-01T00:00:00Z"}]),  # costs
            _mock_table([{"price_per_km": 0.29}]),  # group price_per_km
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/balances",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        balances = {b["userId"]: b["balance"] for b in response.get_json()["balances"]}
        # user-a drove 80/100 km -> owes 80 of the 100 fixed cost; paid the full 100 up front.
        self.assertEqual(balances["user-a"], 20.0)
        self.assertEqual(balances["user-b"], -20.0)

    def test_get_balances_fixed_cost_snapshot_excludes_later_joiner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-a"}, {"user_id": "user-b"}, {"user_id": "user-c"}]),  # group members (3 today)
            _mock_table([
                {"id": "user-a", "first_name": "Ada", "last_name": ""},
                {"id": "user-b", "first_name": "Bo", "last_name": ""},
                {"id": "user-c", "first_name": "Cas", "last_name": ""},
            ]),  # profiles
            _mock_table([]),  # trips (none)
            _mock_table([{"id": "cost-1", "category": "Road tax", "paid_by": "user-a", "amount": 90,
                          "cost_date": "2026-05-01", "notes": None, "participants": ["user-a", "user-b"],
                          "allocation_method": "equal", "created_at": "2026-05-01T00:00:00Z"}]),  # costs, logged before user-c joined
            _mock_table([{"price_per_km": 0.29}]),  # group price_per_km
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/balances",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        balances = {b["userId"]: b["balance"] for b in response.get_json()["balances"]}
        self.assertEqual(balances["user-a"], 45.0)
        self.assertEqual(balances["user-b"], -45.0)
        # user-c joined after this cost was logged, so their snapshot share is zero.
        self.assertEqual(balances["user-c"], 0.0)

    def test_get_balances_personal_summary_for_requesting_user(self):
        self._setup_valid_session(user_id="user-a")
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-a"}, {"user_id": "user-b"}]),  # group members
            _mock_table([{"id": "user-a", "first_name": "Ada", "last_name": ""}, {"id": "user-b", "first_name": "Bo", "last_name": ""}]),  # profiles
            _mock_table([{"id": "trip-1", "odometer_start": 0, "odometer_end": 100, "distance_km": 100, "cost": 50,
                          "notes": None, "trip_date": "2026-06-01", "logged_by": "user-a", "created_at": "2026-06-01T00:00:00Z"}]),  # trips
            _mock_table([{"trip_id": "trip-1", "user_id": "user-a"}]),  # trip_participants (solo trip by user-a)
            _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-b", "amount": 100,
                          "cost_date": "2026-06-01", "notes": None, "participants": None,
                          "allocation_method": None, "created_at": "2026-06-01T00:00:00Z"}]),  # costs (legacy, no snapshot)
            _mock_table([{"price_per_km": 0.29}]),  # group price_per_km
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/balances",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        personal = response.get_json()["personalSummary"]
        # user-a: solo participant on a 100km/€50 trip, plus an equal share (50) of the
        # legacy 100 fixed cost (falls back to today's 2 members since it has no snapshot).
        self.assertEqual(personal["allTime"]["kmDriven"], 100.0)
        self.assertEqual(personal["allTime"]["flexibleCosts"], 50.0)
        self.assertEqual(personal["allTime"]["fixedCosts"], 50.0)
        self.assertEqual(personal["balance"], -100.0)

    def test_create_cost_accepts_multipart_with_photo(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
            _mock_table([{"id": "cost-1", "category": "Car insurance", "paid_by": "user-123", "amount": 62.40,
                          "photo_url": "https://example.com/receipt.jpg"}]),  # insert
        ]
        db_client.storage.from_.return_value.upload.return_value = {}
        db_client.storage.from_.return_value.get_public_url.return_value = {"publicURL": "https://example.com/receipt.jpg"}
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/costs",
            data={
                "category": "Car insurance",
                "paidBy": "user-123",
                "amount": "62.40",
                "photo": (io.BytesIO(b"fake-image-content"), "receipt.jpg"),
            },
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["cost"]["photo_url"], "https://example.com/receipt.jpg")

    def test_create_cost_rejects_non_image_photo(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/groups/group-123/costs",
            data={
                "category": "Car insurance",
                "paidBy": "user-123",
                "amount": "62.40",
                "photo": (io.BytesIO(b"not-an-image"), "receipt.txt", "text/plain"),
            },
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("photo", response.get_json()["fieldErrors"])

    def test_edit_cost_not_found(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([]),  # cost lookup: not found
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123/costs/cost-1",
            json={"amount": 10},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 404)

    def test_edit_cost_updates_amount_and_notes(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"id": "cost-1"}]),  # cost lookup
            _mock_table([{"id": "cost-1", "amount": 75.0, "notes": "Updated"}]),  # update
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123/costs/cost-1",
            json={"amount": 75.0, "notes": "Updated"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()["cost"]
        self.assertEqual(payload["amount"], 75.0)
        self.assertEqual(payload["notes"], "Updated")

    def test_edit_cost_no_changes(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"id": "cost-1"}]),  # cost lookup
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123/costs/cost-1",
            json={},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
