import logging
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from flask import Blueprint, jsonify, request

from supabase_client import db_for, get_token_from_request, get_user_from_token

bp = Blueprint("trips", __name__)
logger = logging.getLogger(__name__)

LARGE_DISTANCE_THRESHOLD_KM = Decimal("150")


def _auth_context():
    token = get_token_from_request(request)
    if not token:
        return None, None, (jsonify({"error": "Authorization header required"}), 401)

    user = get_user_from_token(token)
    if not user:
        return None, None, (jsonify({"error": "Invalid or expired session"}), 401)

    return token, user, None


def _require_membership(client, group_id: str, user_id: str) -> bool:
    membership = (
        client.table("group_members")
        .select("id")
        .eq("group_id", group_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    return bool(membership.data)


def _to_decimal(value):
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _friendly_error(message: str, can_retry: bool = False):
    payload = {"error": message}
    if can_retry:
        payload["retry"] = True
    return payload


def _is_supported_image(file) -> bool:
    mimetype = (file.mimetype or "").lower()
    return mimetype.startswith("image/")


def _upload_trip_photo_to_storage(client, group_id: str, file):
    mimetype = (file.mimetype or "").lower()
    if not mimetype.startswith("image/"):
        return None, "Only image uploads are allowed"

    bucket_name = os.getenv("TRIP_PHOTO_BUCKET", "trip-photos")
    extension = (file.filename.rsplit(".", 1)[-1] if file.filename and "." in file.filename else "jpg").lower()
    object_path = f"{group_id}/{uuid.uuid4()}.{extension}"

    upload_result = client.storage.from_(bucket_name).upload(
        object_path,
        file.read(),
        {"content-type": mimetype, "upsert": "true"},
    )

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


def _get_latest_trip(client, group_id: str):
    result = (
        client.table("trips")
        .select("id, odometer_reading")
        .eq("group_id", group_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def _get_group_price_per_km(client, group_id: str):
    result = (
        client.table("car_sharing_groups")
        .select("price_per_km")
        .eq("id", group_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None
    return _to_decimal(result.data[0].get("price_per_km"))


def _profile_name(profile: dict) -> str:
    first_name = (profile.get("first_name") or "").strip()
    last_name = (profile.get("last_name") or "").strip()
    return " ".join(part for part in [first_name, last_name] if part).strip() or "Member"


def _serialize_trip(row: dict, profile_by_id: dict, participant_ids_by_trip: dict, latest_trip_id) -> dict:
    participant_ids = participant_ids_by_trip.get(row["id"], [])
    participants = [
        {"userId": pid, "name": _profile_name(profile_by_id.get(pid, {}))}
        for pid in participant_ids
    ]
    return {
        "id": row["id"],
        "loggedBy": row.get("logged_by"),
        "loggedByName": _profile_name(profile_by_id.get(row.get("logged_by"), {})),
        "odometerReading": row.get("odometer_reading"),
        "previousOdometerReading": row.get("previous_odometer_reading"),
        "distanceKm": row.get("distance_km"),
        "cost": row.get("cost"),
        "pricePerKm": row.get("price_per_km_snapshot"),
        "photoUrl": row.get("photo_url"),
        "notes": row.get("notes"),
        "tripDate": row.get("trip_date"),
        "provisional": row.get("provisional", True),
        "editedAt": row.get("edited_at"),
        "createdAt": row.get("created_at"),
        "isEditable": row["id"] == latest_trip_id,
        "participants": participants,
    }


@bp.route("/api/groups/<group_id>/trips", methods=["GET"])
def list_trips(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        trip_rows = (
            client.table("trips")
            .select(
                "id, logged_by, odometer_reading, previous_odometer_reading, distance_km, cost, "
                "price_per_km_snapshot, photo_url, notes, trip_date, provisional, edited_at, created_at"
            )
            .eq("group_id", group_id)
            .order("created_at", desc=True)
            .execute()
        )
        trips = trip_rows.data or []
        trip_ids = [row["id"] for row in trips]

        participant_ids_by_trip = {}
        if trip_ids:
            participant_rows = (
                client.table("trip_participants")
                .select("trip_id, user_id")
                .in_("trip_id", trip_ids)
                .execute()
            )
            for row in (participant_rows.data or []):
                participant_ids_by_trip.setdefault(row["trip_id"], []).append(row["user_id"])

        profile_ids = {row["logged_by"] for row in trips if row.get("logged_by")}
        for ids in participant_ids_by_trip.values():
            profile_ids.update(ids)

        profile_by_id = {}
        if profile_ids:
            profiles = (
                client.table("profiles")
                .select("id, first_name, last_name")
                .in_("id", list(profile_ids))
                .execute()
            )
            profile_by_id = {row["id"]: row for row in (profiles.data or [])}

        latest_trip_id = trips[0]["id"] if trips else None
        total_km = sum((Decimal(str(row["distance_km"])) for row in trips if row.get("distance_km") is not None), Decimal("0"))
        total_cost = sum((Decimal(str(row["cost"])) for row in trips if row.get("cost") is not None), Decimal("0"))

        serialized = [_serialize_trip(row, profile_by_id, participant_ids_by_trip, latest_trip_id) for row in trips]

        return jsonify({
            "trips": serialized,
            "summary": {"totalKm": float(total_km), "totalCost": float(total_cost)},
        }), 200

    except Exception as exc:
        logger.error(f"Failed to list trips for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't load trips right now. Please try again.")), 500


@bp.route("/api/groups/<group_id>/trips", methods=["POST"])
def log_trip(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else dict(request.form)
    body = body or {}
    photo = request.files.get("photo")

    if request.is_json:
        participant_ids = [str(pid) for pid in (body.get("participantIds") or [])]
    else:
        participant_ids = request.form.getlist("participantIds")
    participant_ids = list(dict.fromkeys(pid for pid in participant_ids if pid))

    field_errors = {}

    odometer_reading = _to_decimal(body.get("odometerReading"))
    if odometer_reading is None or odometer_reading < 0:
        field_errors["odometerReading"] = "Enter a valid odometer reading"

    if not participant_ids:
        field_errors["participantIds"] = "Select at least one participant"

    trip_date_raw = str(body.get("tripDate") or "").strip()
    trip_date_value = None
    if trip_date_raw:
        try:
            trip_date_value = datetime.strptime(trip_date_raw, "%Y-%m-%d").date()
        except ValueError:
            field_errors["tripDate"] = "Enter a valid date"

    if photo and not _is_supported_image(photo):
        field_errors["photo"] = "Only image uploads are allowed"

    if field_errors:
        return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": field_errors}), 400

    notes = str(body.get("notes") or "").strip() or None
    confirm_large_distance = _as_bool(body.get("confirmLargeDistance"))

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        member_rows = (
            client.table("group_members")
            .select("user_id")
            .eq("group_id", group_id)
            .execute()
        )
        member_ids = {row["user_id"] for row in (member_rows.data or [])}
        invalid_participants = [pid for pid in participant_ids if pid not in member_ids]
        if invalid_participants:
            return jsonify({
                "error": "One or more selected participants aren't in this group",
                "fieldErrors": {"participantIds": "Select only current group members"},
            }), 400

        latest_trip = _get_latest_trip(client, group_id)
        previous_reading = _to_decimal(latest_trip["odometer_reading"]) if latest_trip else None

        if previous_reading is not None and odometer_reading < previous_reading:
            return jsonify({
                "error": "Odometer reading can't be lower than the previous reading",
                "fieldErrors": {"odometerReading": f"Must be at least {previous_reading} km"},
            }), 400

        distance_km = (odometer_reading - previous_reading) if previous_reading is not None else None

        if distance_km is not None and distance_km > LARGE_DISTANCE_THRESHOLD_KM and not confirm_large_distance:
            return jsonify({
                "error": f"This trip is {distance_km} km, which is unusually long. Confirm to log it anyway.",
                "requiresConfirmation": True,
                "distanceKm": float(distance_km),
            }), 400

        price_per_km = _get_group_price_per_km(client, group_id) or Decimal("0")
        cost = (distance_km * price_per_km) if distance_km is not None else None

        photo_url = None
        if photo:
            photo_url, upload_error = _upload_trip_photo_to_storage(client, group_id, photo)
            if upload_error:
                return jsonify({"error": upload_error, "fieldErrors": {"photo": upload_error}}), 400

        trip_insert = {
            "group_id": group_id,
            "logged_by": str(user.id),
            "odometer_reading": float(odometer_reading),
            "previous_odometer_reading": float(previous_reading) if previous_reading is not None else None,
            "distance_km": float(distance_km) if distance_km is not None else None,
            "price_per_km_snapshot": float(price_per_km),
            "cost": float(cost) if cost is not None else None,
            "photo_url": photo_url,
            "notes": notes,
            "large_distance_confirmed": bool(
                distance_km is not None and distance_km > LARGE_DISTANCE_THRESHOLD_KM
            ),
        }
        if trip_date_value:
            trip_insert["trip_date"] = trip_date_value.isoformat()

        result = client.table("trips").insert(trip_insert).execute()
        if not result.data:
            return jsonify(_friendly_error("We couldn't save this trip right now. Please retry.", can_retry=True)), 500

        trip = result.data[0]

        participant_rows = [{"trip_id": trip["id"], "user_id": pid} for pid in participant_ids]
        participant_result = client.table("trip_participants").insert(participant_rows).execute()
        if not participant_result.data:
            client.table("trips").delete().eq("id", trip["id"]).execute()
            return jsonify(_friendly_error("We couldn't save this trip right now. Please retry.", can_retry=True)), 500

        return jsonify({"trip": trip}), 201

    except Exception as exc:
        logger.error(f"Failed to log trip for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't save this trip right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/trips/<trip_id>", methods=["PATCH"])
def edit_trip(group_id: str, trip_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else dict(request.form)
    body = body or {}

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        # v1 only allows editing the most recent trip: an earlier trip's distance is used
        # as the baseline for every later trip, so changing it would require recomputing
        # every trip after it. Out of scope for now -- see CLAUDE.md "Wrong entry" edge case.
        latest_trip = _get_latest_trip(client, group_id)
        if not latest_trip or latest_trip["id"] != trip_id:
            return jsonify({"error": "Only the most recent trip can be edited"}), 400

        trip_result = (
            client.table("trips")
            .select("id, previous_odometer_reading, price_per_km_snapshot")
            .eq("id", trip_id)
            .limit(1)
            .execute()
        )
        if not trip_result.data:
            return jsonify({"error": "Trip not found"}), 404
        trip = trip_result.data[0]

        updates = {}
        field_errors = {}

        if "odometerReading" in body:
            odometer_reading = _to_decimal(body.get("odometerReading"))
            previous_reading = _to_decimal(trip.get("previous_odometer_reading"))
            if odometer_reading is None or odometer_reading < 0:
                field_errors["odometerReading"] = "Enter a valid odometer reading"
            elif previous_reading is not None and odometer_reading < previous_reading:
                field_errors["odometerReading"] = f"Must be at least {previous_reading} km"
            else:
                distance_km = (odometer_reading - previous_reading) if previous_reading is not None else None
                price_per_km = _to_decimal(trip.get("price_per_km_snapshot")) or Decimal("0")
                updates["odometer_reading"] = float(odometer_reading)
                updates["distance_km"] = float(distance_km) if distance_km is not None else None
                updates["cost"] = float(distance_km * price_per_km) if distance_km is not None else None

        if "notes" in body:
            updates["notes"] = str(body.get("notes") or "").strip() or None

        if field_errors:
            return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": field_errors}), 400
        if not updates:
            return jsonify({"error": "No changes to save"}), 400

        updates["edited_at"] = datetime.now(timezone.utc).isoformat()
        updates["edited_by"] = str(user.id)

        result = client.table("trips").update(updates).eq("id", trip_id).execute()
        if not result.data:
            return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500

        return jsonify({"trip": result.data[0]}), 200

    except Exception as exc:
        logger.error(f"Failed to edit trip {trip_id} in group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500
