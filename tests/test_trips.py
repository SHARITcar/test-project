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


class TripsRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.trips", None)
        cls.trips_module = importlib.import_module("routes.trips")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.trips_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123", email="test@example.com"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(id=user_id, email=email)

    def test_list_trips_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.get("/api/groups/group-123/trips")
        self.assertEqual(response.status_code, 401)

    def test_list_trips_rejects_non_member(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/trips",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 404)

    def test_list_trips_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),
            _mock_table([
                {"id": "trip-2", "logged_by": "user-123", "odometer_reading": 120, "previous_odometer_reading": 100,
                 "distance_km": 20, "cost": 9.0, "price_per_km_snapshot": 0.45, "photo_url": None,
                 "notes": None, "trip_date": "2026-08-18", "edited_at": None, "created_at": "2026-08-18T10:00:00Z"},
                {"id": "trip-1", "logged_by": "user-123", "odometer_reading": 100, "previous_odometer_reading": None,
                 "distance_km": None, "cost": None, "price_per_km_snapshot": 0.45, "photo_url": None,
                 "notes": None, "trip_date": "2026-08-17", "edited_at": None, "created_at": "2026-08-17T10:00:00Z"},
            ]),
            _mock_table([
                {"trip_id": "trip-2", "user_id": "user-123"},
                {"trip_id": "trip-1", "user_id": "user-123"},
            ]),
            _mock_table([{"id": "user-123", "first_name": "Ada", "last_name": "Lovelace"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/trips",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["trips"]), 2)
        self.assertEqual(payload["summary"]["totalKm"], 20.0)
        self.assertTrue(payload["trips"][0]["isEditable"])
        self.assertFalse(payload["trips"][1]["isEditable"])

    def test_log_trip_validation_error(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "not-a-number"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("odometerReading", response.get_json()["fieldErrors"])

    def test_log_trip_requires_participants(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "100"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("participantIds", response.get_json()["fieldErrors"])

    def test_log_trip_rejects_lower_reading(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),
            _mock_table([{"user_id": "user-123"}]),  # group members (participant validation)
            _mock_table([{"id": "trip-1", "odometer_reading": 500}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "400", "participantIds": "user-123"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("odometerReading", response.get_json()["fieldErrors"])

    def test_log_trip_rejects_non_member_participant(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),
            _mock_table([{"user_id": "user-123"}]),  # group members
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "100", "participantIds": "user-999"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("participantIds", response.get_json()["fieldErrors"])

    def test_log_trip_first_reading_sets_baseline(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
            _mock_table([]),  # no previous trip
            _mock_table([{"price_per_km": 0.45}]),  # group price
            _mock_table([{"id": "trip-1", "odometer_reading": 100, "distance_km": None, "cost": None}]),  # insert trip
            _mock_table([{"trip_id": "trip-1", "user_id": "user-123"}]),  # insert participants
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "100", "participantIds": "user-123"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertIsNone(payload["trip"]["distance_km"])

    def test_log_trip_requires_confirmation_for_large_distance(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
            _mock_table([{"id": "trip-1", "odometer_reading": 100}]),  # previous trip
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "300", "participantIds": "user-123"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertTrue(payload["requiresConfirmation"])
        self.assertEqual(payload["distanceKm"], 200.0)

    def test_log_trip_success_with_confirmation(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"user_id": "user-123"}]),  # group members
            _mock_table([{"id": "trip-1", "odometer_reading": 100}]),  # previous trip
            _mock_table([{"price_per_km": 0.45}]),  # group price
            _mock_table([{"id": "trip-2", "odometer_reading": 300, "distance_km": 200, "cost": 90.0}]),  # insert trip
            _mock_table([{"trip_id": "trip-2", "user_id": "user-123"}]),  # insert participants
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/trips",
            data={"odometerReading": "300", "confirmLargeDistance": "true", "participantIds": "user-123"},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["trip"]["distance_km"], 200)
        self.assertEqual(payload["trip"]["cost"], 90.0)

    def test_edit_trip_rejects_non_latest_trip(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"id": "trip-2", "odometer_reading": 300}]),  # latest trip is trip-2
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123/trips/trip-1",
            json={"odometerReading": 250},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_edit_trip_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership
            _mock_table([{"id": "trip-1", "odometer_reading": 300}]),  # latest trip
            _mock_table([{"id": "trip-1", "previous_odometer_reading": 100, "price_per_km_snapshot": 0.45}]),  # trip detail
            _mock_table([{"id": "trip-1", "odometer_reading": 310, "distance_km": 210, "cost": 94.5}]),  # update
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123/trips/trip-1",
            json={"odometerReading": 310},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["trip"]["odometer_reading"], 310)


if __name__ == "__main__":
    unittest.main()
