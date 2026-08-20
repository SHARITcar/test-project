import json
import logging
import os
import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import certifi
from flask import Blueprint, jsonify, request

from supabase_client import db_for, get_token_from_request, get_user_from_token, supabase

bp = Blueprint("groups", __name__)
logger = logging.getLogger(__name__)

MAX_GROUP_NAME_LENGTH = 120
FIXED_COST_SPLIT_METHODS = ("equal", "per_km")
PRICE_PER_KM_MODES = ("auto", "manual")
FUEL_COUNTRIES = ("NL", "BE", "DE")
MIN_PRICE_PER_KM = Decimal("0.0001")
MAX_PRICE_PER_KM = Decimal("100")
MAX_PARTICIPANTS_PREVIEW = 10


def _auth_context():
    token = get_token_from_request(request)
    if not token:
        return None, None, (jsonify({"error": "Authorization header required"}), 401)

    user = get_user_from_token(token)
    if not user:
        return None, None, (jsonify({"error": "Invalid or expired session"}), 401)

    return token, user, None


def _to_decimal(value):
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _load_json_field(raw_value, default):
    if raw_value is None or raw_value == "":
        return default

    if isinstance(raw_value, (dict, list)):
        return raw_value

    try:
        return json.loads(raw_value)
    except (TypeError, ValueError):
        return None


def _build_invite_link(base_url: str, token: str) -> str:
    app_base = base_url.rstrip("/")
    return f"{app_base}/invite/{token}"


def _extract_invite_token(invite_link: str | None) -> str | None:
    if not invite_link:
        return None
    marker = "/invite/"
    if marker not in invite_link:
        return None
    token = invite_link.split(marker, 1)[1].strip().strip("/")
    return token or None


def _generate_unique_invite_token(client) -> str | None:
    for _ in range(5):
        invite_token = secrets.token_urlsafe(24)

        existing_token = (
            client.table("invitation_links")
            .select("id")
            .eq("token", invite_token)
            .limit(1)
            .execute()
        )
        if existing_token.data:
            continue

        existing_legacy_link = (
            client.table("car_sharing_groups")
            .select("id")
            .eq("invite_link", _build_invite_link(os.getenv("APP_BASE_URL", "http://localhost:5000"), invite_token))
            .limit(1)
            .execute()
        )
        if not existing_legacy_link.data:
            return invite_token

    return None


def _is_invite_token_available(client, invite_token: str) -> bool:
    if not invite_token:
        return False
    existing_token = (
        client.table("invitation_links")
        .select("id")
        .eq("token", invite_token)
        .limit(1)
        .execute()
    )
    if existing_token.data:
        return False

    existing_legacy_link = (
        client.table("car_sharing_groups")
        .select("id")
        .eq("invite_link", _build_invite_link(os.getenv("APP_BASE_URL", "http://localhost:5000"), invite_token))
        .limit(1)
        .execute()
    )
    return not existing_legacy_link.data


def _generate_unique_invite_link(client, app_base_url: str) -> str | None:
    invite_token = _generate_unique_invite_token(client)
    if not invite_token:
        return None
    return _build_invite_link(app_base_url, invite_token)


def _is_link_expired(expires_at) -> bool:
    if not expires_at:
        return False
    if isinstance(expires_at, datetime):
        expires_dt = expires_at
    else:
        raw = str(expires_at).strip().replace("Z", "+00:00")
        try:
            expires_dt = datetime.fromisoformat(raw)
        except ValueError:
            return False
    if expires_dt.tzinfo is None:
        expires_dt = expires_dt.replace(tzinfo=timezone.utc)
    return expires_dt <= datetime.now(timezone.utc)


def _invitation_is_usable(invitation: dict | None) -> bool:
    if not invitation:
        return False
    if not invitation.get("is_active", True):
        return False
    if _is_link_expired(invitation.get("expires_at")):
        return False

    max_uses = invitation.get("max_uses")
    use_count = invitation.get("use_count") or 0
    if max_uses is not None:
        try:
            if int(use_count) >= int(max_uses):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _lookup_invitation_by_token(client, token: str):
    invitation_result = (
        client.table("invitation_links")
        .select("id, group_id, token, created_at, expires_at, max_uses, use_count, is_active")
        .eq("token", token)
        .limit(1)
        .execute()
    )
    if invitation_result.data:
        return invitation_result.data[0], False

    legacy_link = _build_invite_link(os.getenv("APP_BASE_URL", "http://localhost:5000"), token)
    group_result = (
        client.table("car_sharing_groups")
        .select("id, created_at")
        .eq("invite_link", legacy_link)
        .limit(1)
        .execute()
    )
    if not group_result.data:
        return None, False

    group = group_result.data[0]
    return {
        "id": None,
        "group_id": group["id"],
        "token": token,
        "created_at": group.get("created_at"),
        "expires_at": None,
        "max_uses": None,
        "use_count": 0,
        "is_active": True,
    }, True


def _get_profile(client, user_id: str):
    return (
        client.table("profiles")
        .select("id, onboarding_completed, active_group_id")
        .eq("id", user_id)
        .single()
        .execute()
    )


def _friendly_error(message: str, can_retry: bool = False):
    payload = {"error": message}
    if can_retry:
        payload["retry"] = True
    return payload


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _upload_group_photo_to_storage(client, group_id: str, file):
    mimetype = (file.mimetype or "").lower()
    if not mimetype.startswith("image/"):
        return None, "Only image uploads are allowed"

    bucket_name = os.getenv("GROUP_PHOTO_BUCKET", "group-photos")
    extension = (file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "jpg").lower()
    object_path = f"{group_id}/{uuid.uuid4()}.{extension}"

    upload_result = client.storage.from_(bucket_name).upload(
        object_path,
        file.read(),
        {"content-type": mimetype, "upsert": "true"},
    )

    # supabase-py may return a dict or object; detect errors defensively.
    if isinstance(upload_result, dict) and upload_result.get("error"):
        raise RuntimeError(upload_result["error"])

    public_result = client.storage.from_(bucket_name).get_public_url(object_path)
    if isinstance(public_result, dict):
        photo_url = public_result.get("publicURL") or public_result.get("public_url")
    else:
        photo_url = str(public_result)

    if not photo_url:
        raise RuntimeError("Could not resolve uploaded photo URL")

    return photo_url, None


def _is_supported_image(file) -> bool:
    mimetype = (file.mimetype or "").lower()
    return mimetype.startswith("image/")


def _has_required_shipping_fields(address: dict | None) -> bool:
    if not isinstance(address, dict):
        return False
    street = str(address.get("street", "")).strip()
    city = str(address.get("city", "")).strip()
    postal_code = str(
        address.get("postalCode", address.get("postal_code", ""))
    ).strip()
    return bool(street and city and postal_code)


def _validate_group_payload(payload: dict):
    errors = {}

    group_name = (payload.get("groupName") or "").strip()
    license_plate = (payload.get("licensePlate") or "").strip() or None
    if not group_name:
        errors["groupName"] = "Group name is required"
    elif len(group_name) > MAX_GROUP_NAME_LENGTH:
        errors["groupName"] = "Group name is too long"

    price_per_km = _to_decimal(payload.get("pricePerKilometer"))
    if price_per_km is None:
        errors["pricePerKilometer"] = "Price per kilometer must be a number"
    elif price_per_km < MIN_PRICE_PER_KM or price_per_km > MAX_PRICE_PER_KM:
        errors["pricePerKilometer"] = "Price per kilometer must be between 0.0001 and 100"

    price_per_km_mode = (payload.get("pricePerKmMode") or "manual").strip()
    if price_per_km_mode not in PRICE_PER_KM_MODES:
        errors["pricePerKmMode"] = "Price mode must be 'auto' or 'manual'"

    fuel_country = (payload.get("fuelCountry") or "NL").strip()
    if fuel_country not in FUEL_COUNTRIES:
        errors["fuelCountry"] = "Fuel country must be 'NL', 'BE', or 'DE'"

    reminder_type = (payload.get("reminderType") or "").strip()
    if not reminder_type:
        errors["reminderType"] = "Reminder type is required"

    internal_agreements = payload.get("internalAgreements")
    if internal_agreements is not None and not isinstance(internal_agreements, dict):
        errors["internalAgreements"] = "Internal agreements must be an object"

    fixed_costs = payload.get("fixedCosts") or []
    if not isinstance(fixed_costs, list):
        errors["fixedCosts"] = "Fixed costs must be a list"
        fixed_costs = []

    normalized_costs = []
    for i, cost in enumerate(fixed_costs):
        if not isinstance(cost, dict):
            errors[f"fixedCosts.{i}"] = "Fixed cost entry must be an object"
            continue

        cost_type = (cost.get("type") or "").strip()
        amount = _to_decimal(cost.get("amount"))
        description = (cost.get("description") or "").strip() or None
        split_method = (cost.get("splitMethod") or "equal").strip()

        if not cost_type:
            errors[f"fixedCosts.{i}.type"] = "Cost type is required"
        if amount is None or amount < 0:
            errors[f"fixedCosts.{i}.amount"] = "Amount must be a non-negative number"
        if split_method not in FIXED_COST_SPLIT_METHODS:
            errors[f"fixedCosts.{i}.splitMethod"] = "Split method must be 'equal' or 'per_km'"

        if cost_type and amount is not None and amount >= 0 and split_method in FIXED_COST_SPLIT_METHODS:
            normalized_costs.append(
                {
                    "cost_type": cost_type,
                    "amount": float(amount),
                    "description": description,
                    "split_method": split_method,
                }
            )

    return (
        errors,
        group_name,
        license_plate,
        price_per_km,
        price_per_km_mode,
        fuel_country,
        reminder_type,
        internal_agreements,
        normalized_costs,
    )


RDW_VEHICLE_URL = "https://opendata.rdw.nl/resource/m9d7-ebf2.json"
RDW_FUEL_URL = "https://opendata.rdw.nl/resource/8ys7-d773.json"
PDOK_LOCATIESERVER_URL = "https://api.pdok.nl/bzk/locatieserver/search/v3_1/free"


_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())


def _fetch_json(url: str, timeout: float = 5.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=_SSL_CONTEXT) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as exc:
        logger.warning(f"External lookup failed for {url}: {exc}")
        return None


def _normalize_license_plate(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", raw or "").upper()


@bp.route("/api/vehicle-lookup", methods=["GET"])
def vehicle_lookup():
    """Look up a Dutch license plate via RDW open data: brand, model, year,
    and fuel consumption (used to suggest a price-per-km on group creation)."""
    token, user, error = _auth_context()
    if error:
        return error

    plate = _normalize_license_plate(request.args.get("licensePlate", ""))
    if not plate:
        return jsonify({"found": False}), 200

    vehicle_url = f"{RDW_VEHICLE_URL}?{urllib.parse.urlencode({'kenteken': plate})}"
    vehicles = _fetch_json(vehicle_url)
    if not vehicles:
        return jsonify({"found": False}), 200

    vehicle = vehicles[0]
    year = None
    first_registration = vehicle.get("datum_eerste_toelating")
    if first_registration and len(first_registration) >= 4:
        try:
            year = int(first_registration[:4])
        except ValueError:
            year = None

    consumption = None
    fuel_type = None
    fuel_url = f"{RDW_FUEL_URL}?{urllib.parse.urlencode({'kenteken': plate})}"
    fuel_rows = _fetch_json(fuel_url)
    if fuel_rows:
        fuel_row = fuel_rows[0]
        fuel_type = fuel_row.get("brandstof_omschrijving")
        raw_consumption = fuel_row.get("brandstofverbruik_gecombineerd")
        if raw_consumption:
            try:
                consumption = float(raw_consumption)
            except (TypeError, ValueError):
                consumption = None

    return jsonify({
        "found": True,
        "brand": vehicle.get("merk"),
        "model": vehicle.get("handelsbenaming"),
        "year": year,
        "fuelType": fuel_type,
        "consumptionL100km": consumption,
    }), 200


@bp.route("/api/address-lookup", methods=["GET"])
def address_lookup():
    """Resolve a Dutch postal code + house number to a full address via PDOK
    Locatieserver (public Dutch government geocoding API)."""
    token, user, error = _auth_context()
    if error:
        return error

    postal_code = re.sub(r"\s+", "", (request.args.get("postalCode") or "")).upper()
    house_number = re.sub(r"[^0-9]", "", (request.args.get("houseNumber") or ""))
    if not postal_code or not house_number:
        return jsonify({"found": False}), 200

    query = f"postcode:{postal_code} AND huisnummer:{house_number}"
    lookup_url = f"{PDOK_LOCATIESERVER_URL}?{urllib.parse.urlencode({'q': query, 'rows': 1})}"
    result = _fetch_json(lookup_url)
    docs = ((result or {}).get("response") or {}).get("docs") or []
    if not docs:
        return jsonify({"found": False}), 200

    doc = docs[0]
    street = doc.get("straatnaam") or ""
    house_display = doc.get("huis_nlt") or str(doc.get("huisnummer") or house_number)
    return jsonify({
        "found": True,
        "street": f"{street} {house_display}".strip(),
        "city": doc.get("woonplaatsnaam"),
        "postalCode": doc.get("postcode") or postal_code,
        "country": "Netherlands",
    }), 200


@bp.route("/api/reminder-types", methods=["GET"])
def get_reminder_types():
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        profile = _get_profile(client, str(user.id))
        if not profile.data:
            return jsonify({"error": "Profile not found"}), 404

        if not profile.data.get("onboarding_completed"):
            return jsonify({"error": "Complete onboarding before creating a group"}), 403

        rows = (
            client.table("reminder_types")
            .select("id, name, description, is_physical")
            .order("name")
            .execute()
        )
        return jsonify({"reminder_types": rows.data or []}), 200

    except Exception as exc:
        logger.error(f"Failed to fetch reminder types for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't load reminder options right now. Please try again.")), 500


@bp.route("/api/groups", methods=["GET"])
def list_groups():
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        memberships = (
            client.table("group_members")
            .select("group_id, role, joined_at")
            .eq("user_id", str(user.id))
            .execute()
        )
        membership_rows = memberships.data or []
        group_ids = [row["group_id"] for row in membership_rows if row.get("group_id")]

        groups = []
        if group_ids:
            groups_result = (
                client.table("car_sharing_groups")
                .select("id, name, license_plate, photo_url, price_per_km, reminder_type, invite_link, created_at, created_by")
                .in_("id", group_ids)
                .execute()
            )
            group_map = {row["id"]: row for row in (groups_result.data or [])}
            for membership in membership_rows:
                group = group_map.get(membership.get("group_id"))
                if not group:
                    continue
                group = dict(group)
                group["role"] = membership.get("role")
                group["joined_at"] = membership.get("joined_at")
                groups.append(group)

        profile = _get_profile(client, str(user.id))
        active_group_id = None
        if profile.data:
            active_group_id = profile.data.get("active_group_id")

        return jsonify({"groups": groups, "active_group_id": active_group_id}), 200

    except Exception as exc:
        logger.error(f"Failed to load groups for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't load your groups right now. Please try again.")), 500


@bp.route("/api/groups/invite-preview", methods=["GET"])
def invite_preview():
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        app_base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
        invite_link = _generate_unique_invite_link(client, app_base_url)
        if not invite_link:
            return jsonify({"error": "Could not generate invite link"}), 500
        return jsonify({"inviteLink": invite_link}), 200

    except Exception as exc:
        logger.error(f"Failed invite preview for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't generate an invite link right now.")), 500


@bp.route("/api/groups/<group_id>/invite-link", methods=["POST"])
def generate_group_invite_link(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else {}
    body = body or {}
    expires_at = body.get("expiresAt")
    max_uses = body.get("maxUses")

    if max_uses is not None:
        try:
            max_uses = int(max_uses)
            if max_uses <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "maxUses must be a positive integer"}), 400

    try:
        client = db_for(token)
        membership = (
            client.table("group_members")
            .select("id")
            .eq("group_id", group_id)
            .eq("user_id", str(user.id))
            .limit(1)
            .execute()
        )
        if not membership.data:
            return jsonify({"error": "Group not found or access denied"}), 404

        invite_token = _generate_unique_invite_token(client)
        if not invite_token:
            return jsonify(_friendly_error("Could not generate invite link. Please retry.", can_retry=True)), 500

        app_base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
        invite_link = _build_invite_link(app_base_url, invite_token)
        invitation_payload = {
            "group_id": group_id,
            "token": invite_token,
            "expires_at": expires_at,
            "max_uses": max_uses,
            "use_count": 0,
            "is_active": True,
        }
        invitation_insert = (
            client.table("invitation_links")
            .insert(invitation_payload)
            .execute()
        )
        if not invitation_insert.data:
            return jsonify(_friendly_error("Could not generate invite link. Please retry.", can_retry=True)), 500

        client.table("car_sharing_groups").update({"invite_link": invite_link}).eq("id", group_id).execute()
        created = invitation_insert.data[0]
        return jsonify({
            "inviteLink": invite_link,
            "expiresAt": created.get("expires_at"),
            "maxUses": created.get("max_uses"),
        }), 200

    except Exception as exc:
        logger.error(f"Failed to generate invite link for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't generate an invite link right now. Please retry.", can_retry=True)), 500


@bp.route("/api/invite/<token>", methods=["GET"])
def validate_invite_token(token: str):
    token = (token or "").strip()
    if not token:
        return jsonify({"valid": False, "error": "Invitation link is invalid or has expired"}), 200

    auth_token = get_token_from_request(request)
    auth_user = get_user_from_token(auth_token) if auth_token else None

    try:
        client = db_for(auth_token) if auth_token else supabase
        invitation, is_legacy = _lookup_invitation_by_token(client, token)
        if not _invitation_is_usable(invitation):
            logger.info(f"Invite validation failed for token={token}: invalid_or_expired")
            return jsonify({"valid": False, "error": "Invitation link is invalid or has expired"}), 200

        group_id = invitation.get("group_id")
        group_result = (
            client.table("car_sharing_groups")
            .select("id, name, photo_url, member_count")
            .eq("id", group_id)
            .limit(1)
            .execute()
        )
        if not group_result.data:
            return jsonify({"valid": False, "error": "Invitation link is invalid or has expired"}), 200

        group = group_result.data[0]
        participant_rows = (
            client.table("group_members")
            .select("user_id, joined_at")
            .eq("group_id", group_id)
            .limit(MAX_PARTICIPANTS_PREVIEW)
            .execute()
        )
        participants = []
        profile_by_id = {}
        participant_ids = [row.get("user_id") for row in (participant_rows.data or []) if row.get("user_id")]
        if participant_ids:
            try:
                profiles = (
                    client.table("profiles")
                    .select("id, first_name, last_name")
                    .in_("id", participant_ids)
                    .execute()
                )
                for row in (profiles.data or []):
                    profile_by_id[row.get("id")] = row
            except Exception:
                profile_by_id = {}

        for row in participant_rows.data or []:
            user_id = row.get("user_id")
            profile = profile_by_id.get(user_id) or {}
            first_name = (profile.get("first_name") or "").strip()
            last_name = (profile.get("last_name") or "").strip()
            name = " ".join(part for part in [first_name, last_name] if part).strip() or "Member"
            participants.append({"id": user_id, "name": name})

        is_member = False
        if auth_user:
            membership = (
                client.table("group_members")
                .select("id")
                .eq("group_id", group_id)
                .eq("user_id", str(auth_user.id))
                .limit(1)
                .execute()
            )
            is_member = bool(membership.data)

        logger.info(f"Invite validation success for token={token}: group_id={group_id}")
        return jsonify({
            "valid": True,
            "groupId": group_id,
            "groupName": group.get("name"),
            "groupPhoto": group.get("photo_url"),
            "participants": participants,
            "isMember": is_member,
            "memberCount": group.get("member_count") or len(participants),
            "requiresAuth": auth_user is None,
            "legacyLink": is_legacy,
        }), 200

    except Exception as exc:
        logger.error(f"Failed invite validation for token={token}: {exc}")
        return jsonify(_friendly_error("We couldn't validate this link right now. Please retry.", can_retry=True)), 500


@bp.route("/api/invite/<token>/join", methods=["POST"])
def join_group_via_invite(token: str):
    token = (token or "").strip()
    if not token:
        return jsonify({"success": False, "error": "Invitation link is invalid or has expired"}), 400

    auth_token, user, error = _auth_context()
    if error:
        return error

    membership_id = None
    group_id = None
    invitation_id = None

    try:
        client = db_for(auth_token)
        invitation, is_legacy = _lookup_invitation_by_token(client, token)
        if not _invitation_is_usable(invitation):
            logger.info(f"Invite join blocked for user={user.id} token={token}: invalid_or_expired")
            return jsonify({"success": False, "error": "Invitation link is invalid or has expired"}), 400

        group_id = invitation.get("group_id")
        invitation_id = invitation.get("id")
        existing_member = (
            client.table("group_members")
            .select("id")
            .eq("group_id", group_id)
            .eq("user_id", str(user.id))
            .limit(1)
            .execute()
        )
        if existing_member.data:
            logger.info(f"Invite join no-op for user={user.id} group={group_id}: already_member")
            return jsonify({
                "success": False,
                "error": "User is already a member of this group",
                "groupId": group_id,
            }), 200

        membership_insert = (
            client.table("group_members")
            .insert({
                "group_id": group_id,
                "user_id": str(user.id),
                "role": "member",
            })
            .execute()
        )
        if not membership_insert.data:
            raise RuntimeError("Failed to create group membership")
        membership_id = membership_insert.data[0].get("id")

        if invitation_id:
            try:
                client.table("invitation_link_usage").insert({
                    "invitation_link_id": invitation_id,
                    "user_id": str(user.id),
                    "accepted_at": datetime.now(timezone.utc).isoformat(),
                    "invited_email": user.email,
                }).execute()
            except Exception as usage_exc:
                if "duplicate key" not in str(usage_exc).lower():
                    raise

            if not is_legacy:
                next_use_count = int(invitation.get("use_count") or 0) + 1
                client.table("invitation_links").update({"use_count": next_use_count}).eq("id", invitation_id).execute()

        group_result = (
            client.table("car_sharing_groups")
            .select("member_count")
            .eq("id", group_id)
            .limit(1)
            .execute()
        )
        current_member_count = 0
        if group_result.data:
            current_member_count = int(group_result.data[0].get("member_count") or 0)
        client.table("car_sharing_groups").update({
            "member_count": current_member_count + 1,
            "invite_link": _build_invite_link(os.getenv("APP_BASE_URL", "http://localhost:5000"), token),
        }).eq("id", group_id).execute()

        try:
            client.table("profiles").update({"active_group_id": group_id}).eq("id", str(user.id)).execute()
        except Exception as profile_exc:
            logger.warning(f"Failed to update active_group_id during invite join for user {user.id}: {profile_exc}")

        logger.info(f"Invite join success for user={user.id} group={group_id} membership={membership_id}")
        return jsonify({"success": True, "groupId": group_id, "membershipId": membership_id}), 200

    except Exception as exc:
        logger.error(f"Failed invite join for user={user.id} token={token}: {exc}")
        if membership_id and group_id:
            try:
                rollback_client = db_for(auth_token)
                rollback_client.table("group_members").delete().eq("id", membership_id).eq("user_id", str(user.id)).execute()
            except Exception as rollback_exc:
                logger.error(f"Invite join rollback failed for membership {membership_id}: {rollback_exc}")
        return jsonify(_friendly_error("We couldn't complete your join request right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups", methods=["POST"])
def create_group():
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else dict(request.form)
    body = body or {}

    if not request.is_json:
        body["internalAgreements"] = _load_json_field(body.get("internalAgreements"), {})
        body["fixedCosts"] = _load_json_field(body.get("fixedCosts"), [])
        body["shippingAddress"] = _load_json_field(body.get("shippingAddress"), None)

    (
        errors,
        group_name,
        license_plate,
        price_per_km,
        price_per_km_mode,
        fuel_country,
        reminder_type,
        internal_agreements,
        normalized_costs,
    ) = _validate_group_payload(body)

    if errors:
        return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": errors}), 400

    idempotency_key = (
        request.headers.get("Idempotency-Key")
        or body.get("idempotencyKey")
        or str(uuid.uuid4())
    )

    payment_confirmed = _as_bool(body.get("paymentConfirmed", False))
    shipping_address = body.get("shippingAddress")
    group_photo = request.files.get("groupPhoto")
    if group_photo and not _is_supported_image(group_photo):
        return jsonify(
            {
                "error": "Please correct the highlighted fields",
                "fieldErrors": {"groupPhoto": "Only image uploads are allowed"},
            }
        ), 400

    group_id = None

    try:
        client = db_for(token)

        profile = _get_profile(client, str(user.id))
        if not profile.data:
            return jsonify({"error": "Profile not found"}), 404

        if not profile.data.get("onboarding_completed"):
            return jsonify({"error": "Complete onboarding before creating a group"}), 403

        existing = (
            client.table("car_sharing_groups")
            .select("id, name, license_plate, photo_url, price_per_km, reminder_type, invite_link, created_at")
            .eq("created_by", str(user.id))
            .eq("idempotency_key", idempotency_key)
            .limit(1)
            .execute()
        )
        if existing.data:
            existing_group = existing.data[0]
            return jsonify({
                "group": existing_group,
                "membership": {
                    "user_id": str(user.id),
                    "role": "owner",
                },
                "active_group_id": existing_group["id"],
                "idempotentReplay": True,
            }), 200

        reminder = (
            client.table("reminder_types")
            .select("id, name, is_physical")
            .eq("name", reminder_type)
            .limit(1)
            .execute()
        )
        if not reminder.data:
            return jsonify({"error": "Selected reminder type is not available", "fieldErrors": {"reminderType": "Invalid reminder type"}}), 400

        reminder_row = reminder.data[0]
        if reminder_row.get("is_physical"):
            if not _has_required_shipping_fields(shipping_address):
                return jsonify({
                    "error": "Shipping address is required for a physical reminder",
                    "fieldErrors": {"shippingAddress": "Shipping address with street, city, and postal code is required"},
                }), 400
            if not payment_confirmed:
                return jsonify({
                    "error": "Please complete payment before creating a group with a physical reminder",
                    "fieldErrors": {"paymentConfirmed": "Payment confirmation is required"},
                }), 400

        app_base_url = os.getenv("APP_BASE_URL", "http://localhost:5000")
        requested_invite_token = _extract_invite_token((body.get("inviteLink") or "").strip())
        invite_link = None
        if requested_invite_token and _is_invite_token_available(client, requested_invite_token):
            invite_link = _build_invite_link(app_base_url, requested_invite_token)
        if not invite_link:
            invite_link = _generate_unique_invite_link(client, app_base_url)
        if not invite_link:
            return jsonify(_friendly_error("Could not generate invite link. Please retry.", can_retry=True)), 500

        invite_token = _extract_invite_token(invite_link)
        if not invite_token:
            return jsonify(_friendly_error("Could not generate invite link. Please retry.", can_retry=True)), 500

        group_insert = {
            "name": group_name,
            "license_plate": license_plate,
            "price_per_km": float(price_per_km),
            "price_per_km_mode": price_per_km_mode,
            "fuel_country": fuel_country,
            "reminder_type": reminder_row["name"],
            "internal_agreements": internal_agreements,
            "invite_link": invite_link,
            "member_count": 1,
            "created_by": str(user.id),
            "idempotency_key": idempotency_key,
            "shipping_address": shipping_address,
            "payment_completed": payment_confirmed,
        }

        group_result = (
            client.table("car_sharing_groups")
            .insert(group_insert)
            .execute()
        )

        if not group_result.data:
            return jsonify(_friendly_error("We couldn't create your group right now. Please retry.", can_retry=True)), 500

        group = group_result.data[0]
        group_id = group["id"]

        member_result = (
            client.table("group_members")
            .insert({
                "group_id": group_id,
                "user_id": str(user.id),
                "role": "owner",
            })
            .execute()
        )
        if not member_result.data:
            raise RuntimeError("Failed to create initial membership")

        invitation_insert = (
            client.table("invitation_links")
            .insert(
                {
                    "group_id": group_id,
                    "token": invite_token,
                    "use_count": 0,
                    "is_active": True,
                }
            )
            .execute()
        )
        if not invitation_insert.data:
            raise RuntimeError("Failed to persist invitation metadata")

        if normalized_costs:
            fixed_cost_rows = []
            for cost in normalized_costs:
                fixed_cost_rows.append(
                    {
                        "group_id": group_id,
                        "cost_type": cost["cost_type"],
                        "amount": cost["amount"],
                        "description": cost["description"],
                        "split_method": cost["split_method"],
                    }
                )
            client.table("group_fixed_costs").insert(fixed_cost_rows).execute()

        try:
            client.table("profiles").update({"active_group_id": group_id}).eq("id", str(user.id)).execute()
        except Exception as profile_exc:
            logger.warning(f"Failed to update active_group_id for user {user.id}: {profile_exc}")

        photo_url = group.get("photo_url")
        if group_photo:
            uploaded_url, upload_error = _upload_group_photo_to_storage(client, group_id, group_photo)
            if upload_error:
                raise RuntimeError(upload_error)
            if uploaded_url:
                photo_url = uploaded_url
                client.table("car_sharing_groups").update({"photo_url": photo_url}).eq("id", group_id).execute()

        return jsonify(
            {
                "group": {
                    "id": group_id,
                    "name": group.get("name"),
                    "license_plate": group.get("license_plate"),
                    "photo_url": photo_url,
                    "price_per_km": group.get("price_per_km"),
                    "reminder_type": group.get("reminder_type"),
                    "invite_link": group.get("invite_link"),
                    "created_at": group.get("created_at"),
                },
                "membership": member_result.data[0],
                "active_group_id": group_id,
            }
        ), 201

    except Exception as exc:
        logger.error(f"Failed to create group for {user.id}: {exc}")

        if "duplicate key value" in str(exc).lower() and group_id is None:
            try:
                client = db_for(token)
                existing = (
                    client.table("car_sharing_groups")
                    .select("id, name, license_plate, photo_url, price_per_km, reminder_type, invite_link, created_at")
                    .eq("created_by", str(user.id))
                    .eq("idempotency_key", idempotency_key)
                    .limit(1)
                    .execute()
                )
                if existing.data:
                    return jsonify({
                        "group": existing.data[0],
                        "membership": {
                            "user_id": str(user.id),
                            "role": "owner",
                        },
                        "active_group_id": existing.data[0]["id"],
                        "idempotentReplay": True,
                    }), 200
            except Exception as lookup_exc:
                logger.error(f"Duplicate-key lookup failed for user {user.id}: {lookup_exc}")

        if group_id:
            try:
                rollback_client = db_for(token)
                rollback_client.table("group_fixed_costs").delete().eq("group_id", group_id).execute()
                rollback_client.table("invitation_links").delete().eq("group_id", group_id).execute()
                rollback_client.table("group_members").delete().eq("group_id", group_id).eq("user_id", str(user.id)).execute()
                rollback_client.table("car_sharing_groups").delete().eq("id", group_id).eq("created_by", str(user.id)).execute()
            except Exception as rollback_exc:
                logger.error(f"Rollback failed for group {group_id}: {rollback_exc}")

        return jsonify(_friendly_error("Something went wrong while creating your group. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/photo", methods=["POST"])
def upload_group_photo(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    file = request.files.get("groupPhoto")
    if not file:
        return jsonify({"error": "groupPhoto file is required"}), 400

    try:
        client = db_for(token)
        membership = (
            client.table("group_members")
            .select("id")
            .eq("group_id", group_id)
            .eq("user_id", str(user.id))
            .limit(1)
            .execute()
        )
        if not membership.data:
            return jsonify({"error": "Group not found or access denied"}), 404

        photo_url, upload_error = _upload_group_photo_to_storage(client, group_id, file)
        if upload_error:
            return jsonify({"error": upload_error}), 400

        update_result = (
            client.table("car_sharing_groups")
            .update({"photo_url": photo_url})
            .eq("id", group_id)
            .execute()
        )
        if not update_result.data:
            return jsonify({"error": "Group not found"}), 404

        return jsonify({"photo_url": photo_url, "photoUrl": photo_url}), 200

    except Exception as exc:
        logger.error(f"Failed photo upload for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't upload the photo right now. Please try again.", can_retry=True)), 500


def _require_membership(client, group_id: str, user_id: str):
    membership = (
        client.table("group_members")
        .select("id, role")
        .eq("group_id", group_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    return membership.data[0] if membership.data else None


def _decrement_member_count(client, group_id: str):
    group_result = (
        client.table("car_sharing_groups")
        .select("member_count")
        .eq("id", group_id)
        .limit(1)
        .execute()
    )
    if group_result.data:
        current_count = int(group_result.data[0].get("member_count") or 0)
        client.table("car_sharing_groups").update(
            {"member_count": max(current_count - 1, 0)}
        ).eq("id", group_id).execute()


def _validate_group_update_payload(payload: dict):
    errors = {}
    updates = {}

    if "groupName" in payload:
        group_name = (payload.get("groupName") or "").strip()
        if not group_name:
            errors["groupName"] = "Group name is required"
        elif len(group_name) > MAX_GROUP_NAME_LENGTH:
            errors["groupName"] = "Group name is too long"
        else:
            updates["name"] = group_name

    if "licensePlate" in payload:
        updates["license_plate"] = (payload.get("licensePlate") or "").strip() or None

    if "pricePerKilometer" in payload:
        price_per_km = _to_decimal(payload.get("pricePerKilometer"))
        if price_per_km is None:
            errors["pricePerKilometer"] = "Price per kilometer must be a number"
        elif price_per_km < MIN_PRICE_PER_KM or price_per_km > MAX_PRICE_PER_KM:
            errors["pricePerKilometer"] = "Price per kilometer must be between 0.0001 and 100"
        else:
            updates["price_per_km"] = float(price_per_km)

    if "pricePerKmMode" in payload:
        price_per_km_mode = (payload.get("pricePerKmMode") or "").strip()
        if price_per_km_mode not in PRICE_PER_KM_MODES:
            errors["pricePerKmMode"] = "Price mode must be 'auto' or 'manual'"
        else:
            updates["price_per_km_mode"] = price_per_km_mode

    if "fuelCountry" in payload:
        fuel_country = (payload.get("fuelCountry") or "").strip()
        if fuel_country not in FUEL_COUNTRIES:
            errors["fuelCountry"] = "Fuel country must be 'NL', 'BE', or 'DE'"
        else:
            updates["fuel_country"] = fuel_country

    if "reminderType" in payload:
        reminder_type = (payload.get("reminderType") or "").strip()
        if not reminder_type:
            errors["reminderType"] = "Reminder type is required"
        else:
            updates["reminder_type"] = reminder_type

    if "internalAgreements" in payload:
        internal_agreements = payload.get("internalAgreements")
        if internal_agreements is not None and not isinstance(internal_agreements, dict):
            errors["internalAgreements"] = "Internal agreements must be an object"
        else:
            updates["internal_agreements"] = internal_agreements

    return errors, updates


@bp.route("/api/groups/<group_id>", methods=["GET", "PATCH"])
def group_detail(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        if request.method == "GET":
            group_result = (
                client.table("car_sharing_groups")
                .select(
                    "id, name, license_plate, photo_url, price_per_km, price_per_km_mode, "
                    "fuel_country, reminder_type, "
                    "internal_agreements, invite_link, member_count, created_at"
                )
                .eq("id", group_id)
                .limit(1)
                .execute()
            )
            if not group_result.data:
                return jsonify({"error": "Group not found"}), 404
            return jsonify({"group": group_result.data[0]}), 200

        body = request.get_json(silent=True) or {}
        errors, updates = _validate_group_update_payload(body)
        if errors:
            return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": errors}), 400
        if not updates:
            return jsonify({"error": "No changes to save"}), 400

        if "reminder_type" in updates:
            reminder = (
                client.table("reminder_types")
                .select("name, is_physical")
                .eq("name", updates["reminder_type"])
                .limit(1)
                .execute()
            )
            if not reminder.data:
                return jsonify({
                    "error": "Selected reminder type is not available",
                    "fieldErrors": {"reminderType": "Invalid reminder type"},
                }), 400
            if reminder.data[0].get("is_physical"):
                return jsonify({
                    "error": "Switching to a physical reminder isn't supported from settings yet",
                    "fieldErrors": {"reminderType": "Choose a non-physical reminder, or create a new group for a physical sticker"},
                }), 400

        result = (
            client.table("car_sharing_groups")
            .update(updates)
            .eq("id", group_id)
            .execute()
        )
        if not result.data:
            return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500

        return jsonify({"group": result.data[0]}), 200

    except Exception as exc:
        logger.error(f"Failed to update group {group_id} for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/activate", methods=["POST"])
def activate_group(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        client.table("profiles").update({"active_group_id": group_id}).eq("id", str(user.id)).execute()
        return jsonify({"active_group_id": group_id}), 200

    except Exception as exc:
        logger.error(f"Failed to activate group {group_id} for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't switch groups right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/members", methods=["GET"])
def list_group_members(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        member_rows = (
            client.table("group_members")
            .select("id, user_id, role, joined_at")
            .eq("group_id", group_id)
            .order("joined_at")
            .execute()
        )
        member_rows = member_rows.data or []

        member_ids = [row["user_id"] for row in member_rows if row.get("user_id")]
        profile_by_id = {}
        if member_ids:
            profiles = (
                client.table("profiles")
                .select("id, first_name, last_name, avatar_url")
                .in_("id", member_ids)
                .execute()
            )
            profile_by_id = {row["id"]: row for row in (profiles.data or [])}

        members = []
        for row in member_rows:
            profile = profile_by_id.get(row.get("user_id"), {})
            first_name = (profile.get("first_name") or "").strip()
            last_name = (profile.get("last_name") or "").strip()
            name = " ".join(part for part in [first_name, last_name] if part).strip() or "Member"
            members.append({
                "userId": row.get("user_id"),
                "name": name,
                "avatarUrl": profile.get("avatar_url"),
                "role": row.get("role"),
                "joinedAt": row.get("joined_at"),
            })

        return jsonify({"members": members}), 200

    except Exception as exc:
        logger.error(f"Failed to list members for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't load group members right now. Please try again.")), 500


@bp.route("/api/groups/<group_id>/leave", methods=["POST"])
def leave_group(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        requester_membership = _require_membership(client, group_id, str(user.id))
        if not requester_membership:
            return jsonify({"error": "Group not found or access denied"}), 404

        remaining = (
            client.table("group_members")
            .select("id, user_id, role, joined_at")
            .eq("group_id", group_id)
            .execute()
        )
        remaining_rows = remaining.data or []
        if len(remaining_rows) <= 1:
            return jsonify({
                "error": "You're the last member of this group. Invite someone else before leaving."
            }), 400

        if requester_membership.get("role") == "owner":
            other_owners = [
                row for row in remaining_rows
                if row.get("role") == "owner" and row.get("user_id") != str(user.id)
            ]
            if not other_owners:
                # Last owner leaving: promote someone rather than leave the group ownerless.
                others = [row for row in remaining_rows if row.get("user_id") != str(user.id)]
                if others:
                    successor = min(others, key=lambda row: row.get("joined_at") or "")
                    client.table("group_members").update({"role": "owner"}).eq("id", successor["id"]).execute()

        client.table("group_members").delete().eq("group_id", group_id).eq("user_id", str(user.id)).execute()
        _decrement_member_count(client, group_id)

        return jsonify({"success": True}), 200

    except Exception as exc:
        logger.error(f"Failed to leave group {group_id} for {user.id}: {exc}")
        return jsonify(_friendly_error("We couldn't process leaving the group right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/members/<member_user_id>/remove", methods=["POST"])
def remove_group_member(group_id: str, member_user_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    if member_user_id == str(user.id):
        return jsonify({"error": "Use the leave endpoint to remove yourself"}), 400

    try:
        client = db_for(token)
        requester_membership = _require_membership(client, group_id, str(user.id))
        if not requester_membership:
            return jsonify({"error": "Group not found or access denied"}), 404
        if requester_membership.get("role") != "owner":
            return jsonify({"error": "Only the group owner can remove members"}), 403

        deleted = (
            client.table("group_members")
            .delete()
            .eq("group_id", group_id)
            .eq("user_id", member_user_id)
            .execute()
        )
        if not deleted.data:
            return jsonify({"error": "Member not found in this group"}), 404

        _decrement_member_count(client, group_id)

        return jsonify({"success": True}), 200

    except Exception as exc:
        logger.error(f"Failed to remove member {member_user_id} from group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't remove that member right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/members/<member_user_id>/promote", methods=["POST"])
def promote_group_member(group_id: str, member_user_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        requester_membership = _require_membership(client, group_id, str(user.id))
        if not requester_membership:
            return jsonify({"error": "Group not found or access denied"}), 404
        if requester_membership.get("role") != "owner":
            return jsonify({"error": "Only a group owner can promote members"}), 403

        target = (
            client.table("group_members")
            .select("id, role")
            .eq("group_id", group_id)
            .eq("user_id", member_user_id)
            .limit(1)
            .execute()
        )
        if not target.data:
            return jsonify({"error": "Member not found in this group"}), 404

        target_row = target.data[0]
        if target_row.get("role") != "owner":
            client.table("group_members").update({"role": "owner"}).eq("id", target_row["id"]).execute()

        return jsonify({"success": True, "role": "owner"}), 200

    except Exception as exc:
        logger.error(f"Failed to promote member {member_user_id} in group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't update that member's role right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/members/<member_user_id>/demote", methods=["POST"])
def demote_group_member(group_id: str, member_user_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        requester_membership = _require_membership(client, group_id, str(user.id))
        if not requester_membership:
            return jsonify({"error": "Group not found or access denied"}), 404
        if requester_membership.get("role") != "owner":
            return jsonify({"error": "Only a group owner can demote an owner"}), 403

        member_rows = (
            client.table("group_members")
            .select("id, user_id, role")
            .eq("group_id", group_id)
            .execute()
        )
        rows = member_rows.data or []
        target_row = next((row for row in rows if row.get("user_id") == member_user_id), None)
        if not target_row:
            return jsonify({"error": "Member not found in this group"}), 404

        if target_row.get("role") != "owner":
            return jsonify({"success": True, "role": "member"}), 200

        other_owners = [
            row for row in rows
            if row.get("role") == "owner" and row.get("user_id") != member_user_id
        ]
        if not other_owners:
            return jsonify({"error": "A group must always have at least one owner"}), 400

        client.table("group_members").update({"role": "member"}).eq("id", target_row["id"]).execute()
        return jsonify({"success": True, "role": "member"}), 200

    except Exception as exc:
        logger.error(f"Failed to demote member {member_user_id} in group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't update that member's role right now. Please retry.", can_retry=True)), 500
