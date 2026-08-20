import importlib
import io
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
    mod.get_token_from_request = MagicMock(return_value=None)
    return mod


def _mock_table(result_data):
    table = MagicMock()
    for method_name in ["select", "eq", "single", "limit", "order", "in_", "insert", "update", "delete"]:
        getattr(table, method_name).return_value = table
    table.execute.return_value = SimpleNamespace(data=result_data)
    return table


class GroupsRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake_sc = _make_supabase_client_module()
        sys.modules["supabase_client"] = cls.fake_sc
        sys.modules.pop("routes.groups", None)
        cls.groups_module = importlib.import_module("routes.groups")

    def setUp(self):
        self.fake_sc.supabase.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_user_from_token.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.db_for.reset_mock(return_value=True, side_effect=True)
        self.fake_sc.get_token_from_request.reset_mock(return_value=True, side_effect=True)

        app = Flask(__name__)
        app.register_blueprint(self.groups_module.bp)
        app.testing = True
        self.client = app.test_client()

    def _setup_valid_session(self, user_id="user-123", email="test@example.com"):
        self.fake_sc.get_token_from_request.return_value = "test-access-token"
        self.fake_sc.get_user_from_token.return_value = SimpleNamespace(id=user_id, email=email)

    def test_reminder_types_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.get("/api/reminder-types")
        self.assertEqual(response.status_code, 401)

    def test_reminder_types_requires_onboarding(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": False, "active_group_id": None})
        db_client.table.side_effect = [profile_table]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/reminder-types",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_create_group_validation_errors(self):
        self._setup_valid_session()

        response = self.client.post(
            "/api/groups",
            json={"groupName": "", "pricePerKilometer": "", "reminderType": ""},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("fieldErrors", payload)
        self.assertIn("groupName", payload["fieldErrors"])

    def test_create_group_rejects_invalid_fixed_cost_split_method(self):
        self._setup_valid_session()

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "No reminder",
                "fixedCosts": [{"type": "Road tax", "amount": 120, "splitMethod": "monthly"}],
            },
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("fixedCosts.0.splitMethod", payload["fieldErrors"])

    def test_create_group_rejects_invalid_price_per_km_mode(self):
        self._setup_valid_session()

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "No reminder",
                "pricePerKmMode": "sometimes",
            },
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("pricePerKmMode", response.get_json()["fieldErrors"])

    def test_create_group_rejects_invalid_fuel_country(self):
        self._setup_valid_session()

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "No reminder",
                "fuelCountry": "FR",
            },
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("fuelCountry", response.get_json()["fieldErrors"])

    def test_create_group_success(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None})
        existing_table = _mock_table([])
        reminder_table = _mock_table([{"id": "rt-1", "name": "Push notification", "is_physical": False}])
        invite_token_check = _mock_table([])  # no colliding invitation token
        invite_legacy_check = _mock_table([])  # no colliding legacy link
        insert_group_table = _mock_table([
            {
                "id": "group-123",
                "name": "House car",
                "license_plate": "AB-123",
                "photo_url": None,
                "price_per_km": 0.45,
                "reminder_type": "Push notification",
                "invite_link": "http://localhost:5000/invite/example",
                "created_at": "2026-04-29T00:00:00Z",
            }
        ])
        member_insert_table = _mock_table([
            {"id": "member-1", "group_id": "group-123", "user_id": "user-123", "role": "owner"}
        ])
        invitation_insert_table = _mock_table([{"id": "invite-1", "token": "example"}])
        profile_update_table = _mock_table([{"id": "user-123"}])

        db_client.table.side_effect = [
            profile_table,
            existing_table,
            reminder_table,
            invite_token_check,
            invite_legacy_check,
            insert_group_table,
            member_insert_table,
            invitation_insert_table,
            profile_update_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "licensePlate": "AB-123",
                "pricePerKilometer": 0.45,
                "reminderType": "Push notification",
                "internalAgreements": {},
                "fixedCosts": [],
            },
            headers={
                "Authorization": "Bearer test-access-token",
                "Idempotency-Key": "idem-123",
            },
        )

        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["group"]["id"], "group-123")
        self.assertEqual(payload["active_group_id"], "group-123")

    def test_create_group_idempotent_replay(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None})
        existing_table = _mock_table([
            {
                "id": "group-123",
                "name": "House car",
                "license_plate": "AB-123",
                "photo_url": None,
                "price_per_km": 0.45,
                "reminder_type": "Push notification",
                "invite_link": "http://localhost:5000/invite/example",
                "created_at": "2026-04-29T00:00:00Z",
            }
        ])

        db_client.table.side_effect = [profile_table, existing_table]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "Push notification",
            },
            headers={
                "Authorization": "Bearer test-access-token",
                "Idempotency-Key": "idem-123",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload.get("idempotentReplay"))

    def test_create_group_physical_reminder_requires_shipping_and_payment(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None})
        existing_table = _mock_table([])
        reminder_table = _mock_table([{"id": "rt-2", "name": "Physical sticker", "is_physical": True}])

        db_client.table.side_effect = [profile_table, existing_table, reminder_table]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "Physical sticker",
            },
            headers={"Authorization": "Bearer test-access-token"},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("fieldErrors", payload)
        self.assertIn("shippingAddress", payload["fieldErrors"])

    def test_create_group_physical_reminder_requires_full_shipping_address(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None})
        existing_table = _mock_table([])
        reminder_table = _mock_table([{"id": "rt-2", "name": "Physical sticker", "is_physical": True}])

        db_client.table.side_effect = [profile_table, existing_table, reminder_table]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups",
            json={
                "groupName": "House car",
                "pricePerKilometer": 0.45,
                "reminderType": "Physical sticker",
                "shippingAddress": {"street": "Street 1", "city": "", "postalCode": "1234AB"},
                "paymentConfirmed": True,
            },
            headers={"Authorization": "Bearer test-access-token"},
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("fieldErrors", payload)
        self.assertIn("shippingAddress", payload["fieldErrors"])

    def test_create_group_rejects_non_image_group_photo_before_persist(self):
        self._setup_valid_session()

        response = self.client.post(
            "/api/groups",
            data={
                "groupName": "House car",
                "pricePerKilometer": "0.45",
                "reminderType": "Push notification",
                "groupPhoto": (io.BytesIO(b"not-an-image"), "group.txt", "text/plain"),
            },
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("fieldErrors", payload)
        self.assertIn("groupPhoto", payload["fieldErrors"])
        self.fake_sc.db_for.assert_not_called()

    def test_create_group_accepts_multipart_with_group_photo(self):
        self._setup_valid_session()

        db_client = MagicMock()
        profile_table = _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None})
        existing_table = _mock_table([])
        reminder_table = _mock_table([{"id": "rt-1", "name": "Push notification", "is_physical": False}])
        invite_token_check = _mock_table([])  # no colliding invitation token
        invite_legacy_check = _mock_table([])  # no colliding legacy link
        insert_group_table = _mock_table([
            {
                "id": "group-123",
                "name": "House car",
                "license_plate": "AB-123",
                "photo_url": None,
                "price_per_km": 0.45,
                "reminder_type": "Push notification",
                "invite_link": "http://localhost:5000/invite/example",
                "created_at": "2026-04-29T00:00:00Z",
            }
        ])
        member_insert_table = _mock_table([
            {"id": "member-1", "group_id": "group-123", "user_id": "user-123", "role": "owner"}
        ])
        invitation_insert_table = _mock_table([{"id": "invite-1", "token": "example"}])
        profile_update_table = _mock_table([{"id": "user-123"}])
        group_photo_update_table = _mock_table([{"id": "group-123", "photo_url": "https://example.com/group.jpg"}])

        db_client.table.side_effect = [
            profile_table,
            existing_table,
            reminder_table,
            invite_token_check,
            invite_legacy_check,
            insert_group_table,
            member_insert_table,
            invitation_insert_table,
            profile_update_table,
            group_photo_update_table,
        ]
        db_client.storage.from_.return_value.upload.return_value = {}
        db_client.storage.from_.return_value.get_public_url.return_value = {"publicURL": "https://example.com/group.jpg"}
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups",
            data={
                "groupName": "House car",
                "licensePlate": "AB-123",
                "pricePerKilometer": "0.45",
                "reminderType": "Push notification",
                "internalAgreements": "{}",
                "fixedCosts": "[]",
                "groupPhoto": (io.BytesIO(b"fake-image-content"), "group.jpg"),
            },
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["group"]["photo_url"], "https://example.com/group.jpg")

    def test_upload_group_photo_success(self):
        self._setup_valid_session()

        db_client = MagicMock()
        membership_table = _mock_table([{"id": "membership-1"}])
        group_update_table = _mock_table([{"id": "group-123", "photo_url": "https://example.com/group.jpg"}])
        db_client.table.side_effect = [membership_table, group_update_table]
        db_client.storage.from_.return_value.upload.return_value = {}
        db_client.storage.from_.return_value.get_public_url.return_value = {"publicURL": "https://example.com/group.jpg"}
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/photo",
            data={"groupPhoto": (io.BytesIO(b"fake-image-content"), "group.jpg")},
            headers={"Authorization": "Bearer test-access-token"},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["photo_url"], "https://example.com/group.jpg")
        self.assertEqual(payload["photoUrl"], "https://example.com/group.jpg")

    def test_create_group_allows_multiple_groups_with_different_idempotency_keys(self):
        self._setup_valid_session()

        db_client = MagicMock()
        db_client.table.side_effect = [
            # First create
            _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": None}),
            _mock_table([]),
            _mock_table([{"id": "rt-1", "name": "Push notification", "is_physical": False}]),
            _mock_table([]),  # no colliding invitation token
            _mock_table([]),  # no colliding legacy link
            _mock_table([
                {
                    "id": "group-1",
                    "name": "Group One",
                    "license_plate": None,
                    "photo_url": None,
                    "price_per_km": 0.4,
                    "reminder_type": "Push notification",
                    "invite_link": "http://localhost:5000/invite/one",
                    "created_at": "2026-04-29T00:00:00Z",
                }
            ]),
            _mock_table([{"id": "member-1", "group_id": "group-1", "user_id": "user-123", "role": "owner"}]),
            _mock_table([{"id": "invite-1", "token": "one"}]),  # invitation_links insert
            _mock_table([{"id": "user-123"}]),
            # Second create
            _mock_table({"id": "user-123", "onboarding_completed": True, "active_group_id": "group-1"}),
            _mock_table([]),
            _mock_table([{"id": "rt-1", "name": "Push notification", "is_physical": False}]),
            _mock_table([]),  # no colliding invitation token
            _mock_table([]),  # no colliding legacy link
            _mock_table([
                {
                    "id": "group-2",
                    "name": "Group Two",
                    "license_plate": None,
                    "photo_url": None,
                    "price_per_km": 0.5,
                    "reminder_type": "Push notification",
                    "invite_link": "http://localhost:5000/invite/two",
                    "created_at": "2026-04-29T00:00:00Z",
                }
            ]),
            _mock_table([{"id": "member-2", "group_id": "group-2", "user_id": "user-123", "role": "owner"}]),
            _mock_table([{"id": "invite-2", "token": "two"}]),  # invitation_links insert
            _mock_table([{"id": "user-123"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        first = self.client.post(
            "/api/groups",
            json={
                "groupName": "Group One",
                "pricePerKilometer": 0.40,
                "reminderType": "Push notification",
            },
            headers={
                "Authorization": "Bearer test-access-token",
                "Idempotency-Key": "idem-one",
            },
        )
        second = self.client.post(
            "/api/groups",
            json={
                "groupName": "Group Two",
                "pricePerKilometer": 0.50,
                "reminderType": "Push notification",
            },
            headers={
                "Authorization": "Bearer test-access-token",
                "Idempotency-Key": "idem-two",
            },
        )

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(first.get_json()["group"]["id"], "group-1")
        self.assertEqual(second.get_json()["group"]["id"], "group-2")

    def test_activate_group_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.post("/api/groups/group-123/activate")
        self.assertEqual(response.status_code, 401)

    def test_activate_group_rejects_non_member(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/activate",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 404)

    def test_activate_group_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "member"}]),
            _mock_table([{"id": "user-123", "active_group_id": "group-123"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/activate",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["active_group_id"], "group-123")

    def test_list_group_members_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([
                {"id": "membership-1", "user_id": "user-123", "role": "owner", "joined_at": "2026-04-29T00:00:00Z"},
                {"id": "membership-2", "user_id": "user-456", "role": "member", "joined_at": "2026-04-30T00:00:00Z"},
            ]),
            _mock_table([
                {"id": "user-123", "first_name": "Ada", "last_name": "Lovelace", "avatar_url": None},
                {"id": "user-456", "first_name": "Grace", "last_name": "Hopper", "avatar_url": None},
            ]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123/members",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        members = response.get_json()["members"]
        self.assertEqual(len(members), 2)
        self.assertEqual(members[0]["name"], "Ada Lovelace")
        self.assertEqual(members[0]["role"], "owner")

    def test_leave_group_blocks_last_member(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{"id": "membership-1"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/leave",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_leave_group_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "member"}]),
            _mock_table([
                {"id": "membership-1", "user_id": "user-123", "role": "member", "joined_at": "2026-04-29T00:00:00Z"},
                {"id": "membership-2", "user_id": "user-456", "role": "owner", "joined_at": "2026-04-30T00:00:00Z"},
            ]),
            _mock_table([{"id": "membership-1"}]),
            _mock_table([{"member_count": 2}]),
            _mock_table([{"id": "group-123", "member_count": 1}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/leave",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])

    def test_leave_group_promotes_new_owner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        role_update_table = _mock_table([{"id": "membership-2", "role": "owner"}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([
                {"id": "membership-1", "user_id": "user-123", "role": "owner", "joined_at": "2026-04-29T00:00:00Z"},
                {"id": "membership-2", "user_id": "user-456", "role": "member", "joined_at": "2026-04-30T00:00:00Z"},
                {"id": "membership-3", "user_id": "user-789", "role": "member", "joined_at": "2026-05-01T00:00:00Z"},
            ]),
            role_update_table,
            _mock_table([{"id": "membership-1"}]),
            _mock_table([{"member_count": 3}]),
            _mock_table([{"id": "group-123", "member_count": 2}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/leave",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        role_update_table.update.assert_called_once_with({"role": "owner"})
        role_update_table.eq.assert_any_call("id", "membership-2")

    def test_leave_group_skips_promotion_when_other_owner_exists(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([
                {"id": "membership-1", "user_id": "user-123", "role": "owner", "joined_at": "2026-04-29T00:00:00Z"},
                {"id": "membership-2", "user_id": "user-456", "role": "owner", "joined_at": "2026-04-30T00:00:00Z"},
            ]),
            _mock_table([{"id": "membership-1"}]),  # delete
            _mock_table([{"member_count": 2}]),
            _mock_table([{"id": "group-123", "member_count": 1}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/leave",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])
        # Only 5 table() calls consumed (no role-promotion update) -- another owner remains.
        self.assertEqual(db_client.table.call_count, 5)

    def test_promote_group_member_requires_owner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([{"id": "membership-1", "role": "member"}])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/promote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_promote_group_member_not_found(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/promote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 404)

    def test_promote_group_member_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        target_table = _mock_table([{"id": "membership-2", "role": "member"}])
        update_table = _mock_table([{"id": "membership-2", "role": "owner"}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            target_table,
            update_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/promote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["role"], "owner")
        update_table.update.assert_called_once_with({"role": "owner"})

    def test_promote_group_member_already_owner_is_noop(self):
        self._setup_valid_session()
        db_client = MagicMock()
        target_table = _mock_table([{"id": "membership-2", "role": "owner"}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            target_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/promote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        target_table.update.assert_not_called()

    def test_demote_group_member_requires_owner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([{"id": "membership-1", "role": "member"}])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/demote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_demote_group_member_blocks_last_owner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([
                {"id": "membership-1", "user_id": "user-123", "role": "owner"},
                {"id": "membership-2", "user_id": "user-456", "role": "member"},
            ]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-123/demote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_demote_group_member_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        member_rows_table = _mock_table([
            {"id": "membership-1", "user_id": "user-123", "role": "owner"},
            {"id": "membership-2", "user_id": "user-456", "role": "owner"},
        ])
        update_table = _mock_table([{"id": "membership-2", "role": "member"}])
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            member_rows_table,
            update_table,
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/demote",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["role"], "member")
        update_table.update.assert_called_once_with({"role": "member"})

    def test_remove_group_member_rejects_self(self):
        self._setup_valid_session()
        response = self.client.post(
            "/api/groups/group-123/members/user-123/remove",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)

    def test_remove_group_member_requires_owner(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([{"id": "membership-1", "role": "member"}])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/remove",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_remove_group_member_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{"id": "membership-2"}]),
            _mock_table([{"member_count": 2}]),
            _mock_table([{"id": "group-123", "member_count": 1}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/members/user-456/remove",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["success"])

    def test_group_detail_get_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{
                "id": "group-123",
                "name": "House car",
                "license_plate": "AB-123",
                "photo_url": None,
                "price_per_km": 0.45,
                "reminder_type": "Push notification",
                "internal_agreements": {"keys": "In the hallway drawer"},
                "invite_link": "http://localhost:5000/invite/example",
                "member_count": 2,
                "created_at": "2026-04-29T00:00:00Z",
            }]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/group-123",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["group"]["name"], "House car")

    def test_group_detail_patch_validation_error(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([{"id": "membership-1", "role": "owner"}])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123",
            json={"pricePerKilometer": -1},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("pricePerKilometer", response.get_json()["fieldErrors"])

    def test_group_detail_patch_blocks_physical_reminder_switch(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{"name": "Physical sticker", "is_physical": True}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123",
            json={"reminderType": "Physical sticker"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("reminderType", response.get_json()["fieldErrors"])

    def test_group_detail_patch_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{"id": "group-123", "name": "New name", "price_per_km": 0.5}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123",
            json={"groupName": "New name", "pricePerKilometer": 0.5},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["group"]["name"], "New name")

    def test_group_detail_patch_rejects_invalid_price_per_km_mode(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([{"id": "membership-1", "role": "owner"}])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123",
            json={"pricePerKmMode": "sometimes"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("pricePerKmMode", response.get_json()["fieldErrors"])

    def test_group_detail_patch_updates_price_mode_and_fuel_country(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1", "role": "owner"}]),
            _mock_table([{"id": "group-123", "price_per_km_mode": "auto", "fuel_country": "BE"}]),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.patch(
            "/api/groups/group-123",
            json={"pricePerKmMode": "auto", "fuelCountry": "BE"},
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()["group"]
        self.assertEqual(payload["price_per_km_mode"], "auto")
        self.assertEqual(payload["fuel_country"], "BE")

    def test_list_groups_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"group_id": "group-123", "role": "owner", "joined_at": "2026-04-29T00:00:00Z"}]),
            _mock_table([{"id": "group-123", "name": "House car", "license_plate": None, "photo_url": None,
                           "price_per_km": 0.45, "reminder_type": "Push notification",
                           "invite_link": "http://localhost:5000/invite/example",
                           "created_at": "2026-04-29T00:00:00Z", "created_by": "user-123"}]),
            _mock_table({"id": "user-123", "active_group_id": "group-123"}),
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["groups"]), 1)
        self.assertEqual(payload["active_group_id"], "group-123")

    def test_invite_preview_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([]),  # no colliding invitation token
            _mock_table([]),  # no colliding legacy link
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.get(
            "/api/groups/invite-preview",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("/invite/", response.get_json()["inviteLink"])

    def test_generate_group_invite_link_rejects_non_member(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [_mock_table([])]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/invite-link",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 404)

    def test_generate_group_invite_link_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "membership-1"}]),  # membership check
            _mock_table([]),  # no colliding invitation token
            _mock_table([]),  # no colliding legacy link
            _mock_table([{"id": "invite-1", "token": "abc", "expires_at": None, "max_uses": None}]),  # insert
            _mock_table([{"id": "group-123"}]),  # update group invite_link
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/groups/group-123/invite-link",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("/invite/", response.get_json()["inviteLink"])

    def test_validate_invite_token_rejects_empty_token(self):
        response = self.client.get("/api/invite/")
        self.assertEqual(response.status_code, 404)

    def test_validate_invite_token_success_anonymous(self):
        self.fake_sc.get_token_from_request.return_value = None
        self.fake_sc.supabase.table.side_effect = [
            _mock_table([{"id": "invite-1", "group_id": "group-123", "token": "abc", "created_at": "2026-04-29T00:00:00Z",
                          "expires_at": None, "max_uses": None, "use_count": 0, "is_active": True}]),
            _mock_table([{"id": "group-123", "name": "House car", "photo_url": None, "member_count": 1}]),
            _mock_table([{"user_id": "user-123", "joined_at": "2026-04-29T00:00:00Z"}]),
            _mock_table([{"id": "user-123", "first_name": "Ada", "last_name": "Lovelace"}]),
        ]

        response = self.client.get("/api/invite/abc")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["valid"])
        self.assertTrue(payload["requiresAuth"])
        self.assertEqual(payload["participants"][0]["name"], "Ada Lovelace")

    def test_join_group_via_invite_success(self):
        self._setup_valid_session()
        db_client = MagicMock()
        db_client.table.side_effect = [
            _mock_table([{"id": "invite-1", "group_id": "group-123", "token": "abc", "created_at": "2026-04-29T00:00:00Z",
                          "expires_at": None, "max_uses": None, "use_count": 0, "is_active": True}]),
            _mock_table([]),  # not already a member
            _mock_table([{"id": "membership-1"}]),  # insert membership
            _mock_table([{"id": "usage-1"}]),  # insert usage
            _mock_table([{"id": "invite-1", "use_count": 1}]),  # update use_count
            _mock_table([{"member_count": 1}]),  # select member_count
            _mock_table([{"id": "group-123"}]),  # update member_count + invite_link
            _mock_table([{"id": "user-123"}]),  # update active_group_id
        ]
        self.fake_sc.db_for.return_value = db_client

        response = self.client.post(
            "/api/invite/abc/join",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["groupId"], "group-123")

    def test_vehicle_lookup_requires_token(self):
        self.fake_sc.get_token_from_request.return_value = None
        response = self.client.get("/api/vehicle-lookup?licensePlate=45SNJ5")
        self.assertEqual(response.status_code, 401)

    def test_vehicle_lookup_empty_plate(self):
        self._setup_valid_session()
        response = self.client.get(
            "/api/vehicle-lookup?licensePlate=",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["found"])

    def test_vehicle_lookup_not_found(self):
        self._setup_valid_session()
        with patch.object(self.groups_module, "_fetch_json", return_value=[]):
            response = self.client.get(
                "/api/vehicle-lookup?licensePlate=XX00XX",
                headers={"Authorization": "Bearer test-access-token"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["found"])

    def test_vehicle_lookup_success(self):
        self._setup_valid_session()
        vehicle_response = [{
            "kenteken": "45SNJ5", "merk": "FORD", "handelsbenaming": "KA",
            "datum_eerste_toelating": "20111031",
        }]
        fuel_response = [{
            "brandstof_omschrijving": "Benzine", "brandstofverbruik_gecombineerd": "4.90",
        }]
        with patch.object(self.groups_module, "_fetch_json", side_effect=[vehicle_response, fuel_response]):
            response = self.client.get(
                "/api/vehicle-lookup?licensePlate=45-SNJ-5",
                headers={"Authorization": "Bearer test-access-token"},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["brand"], "FORD")
        self.assertEqual(payload["model"], "KA")
        self.assertEqual(payload["year"], 2011)
        self.assertEqual(payload["consumptionL100km"], 4.9)

    def test_address_lookup_requires_params(self):
        self._setup_valid_session()
        response = self.client.get(
            "/api/address-lookup?postalCode=1012AB",
            headers={"Authorization": "Bearer test-access-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["found"])

    def test_address_lookup_success(self):
        self._setup_valid_session()
        pdok_response = {
            "response": {
                "docs": [{
                    "straatnaam": "Stationsplein",
                    "huis_nlt": "1",
                    "postcode": "1012AB",
                    "woonplaatsnaam": "Amsterdam",
                }]
            }
        }
        with patch.object(self.groups_module, "_fetch_json", return_value=pdok_response):
            response = self.client.get(
                "/api/address-lookup?postalCode=1012AB&houseNumber=1",
                headers={"Authorization": "Bearer test-access-token"},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["street"], "Stationsplein 1")
        self.assertEqual(payload["city"], "Amsterdam")
        self.assertEqual(payload["country"], "Netherlands")


if __name__ == "__main__":
    unittest.main()
