import logging
import os
import uuid
from datetime import date, datetime
from decimal import Decimal, InvalidOperation

from flask import Blueprint, jsonify, request

from supabase_client import db_for, get_token_from_request, get_user_from_token

bp = Blueprint("costs", __name__)
logger = logging.getLogger(__name__)

ALLOWED_CATEGORIES = ("Car insurance", "Road tax", "Parking permit", "Fixed depreciation")
ALLOCATION_METHODS = ("equal", "per_km")


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


def _friendly_error(message: str, can_retry: bool = False):
    payload = {"error": message}
    if can_retry:
        payload["retry"] = True
    return payload


def _is_supported_image(file) -> bool:
    mimetype = (file.mimetype or "").lower()
    return mimetype.startswith("image/")


def _upload_cost_photo_to_storage(client, group_id: str, file):
    mimetype = (file.mimetype or "").lower()
    if not mimetype.startswith("image/"):
        return None, "Only image uploads are allowed"

    bucket_name = os.getenv("COST_PHOTO_BUCKET", "cost-photos")
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


def _profile_name(profile: dict) -> str:
    first_name = (profile.get("first_name") or "").strip()
    last_name = (profile.get("last_name") or "").strip()
    return " ".join(part for part in [first_name, last_name] if part).strip() or "Member"


def _get_group_members(client, group_id: str):
    rows = client.table("group_members").select("user_id").eq("group_id", group_id).execute()
    return [row["user_id"] for row in (rows.data or [])]


def _get_profiles_by_id(client, user_ids):
    if not user_ids:
        return {}
    rows = (
        client.table("profiles")
        .select("id, first_name, last_name")
        .in_("id", list(user_ids))
        .execute()
    )
    return {row["id"]: row for row in (rows.data or [])}


def _get_trips_with_participants(client, group_id: str):
    """Flexible (fuel) costs: each trip is priced automatically at the rate active when it
    was logged (price_per_km_snapshot, i.e. ratePerKmAtTimeOfTrip) and split evenly among
    that trip's participants -- a real charge, not just a usage weight."""
    trip_rows = (
        client.table("trips")
        .select("id, odometer_start, odometer_end, distance_km, cost, notes, trip_date, logged_by, created_at")
        .eq("group_id", group_id)
        .execute()
    )
    trips = trip_rows.data or []
    trip_ids = [row["id"] for row in trips]

    participants_by_trip = {}
    if trip_ids:
        participant_rows = (
            client.table("trip_participants")
            .select("trip_id, user_id")
            .in_("trip_id", trip_ids)
            .execute()
        )
        for row in (participant_rows.data or []):
            participants_by_trip.setdefault(row["trip_id"], []).append(row["user_id"])

    return trips, participants_by_trip


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
    return result.data[0].get("price_per_km")


def _period_stats(trips: list, costs: list, since_date: str | None, price_per_km):
    """km driven, flexible (fuel/trip) costs, and fixed costs since a given ISO date
    (or all-time if since_date is None). trip_date/cost_date are ISO strings, so plain
    string comparison sorts correctly."""
    km = Decimal("0")
    flexible_costs = Decimal("0")
    for row in trips:
        trip_date = row.get("trip_date")
        if since_date and (not trip_date or trip_date < since_date):
            continue
        if row.get("distance_km") is not None:
            km += Decimal(str(row["distance_km"]))
        if row.get("cost") is not None:
            flexible_costs += Decimal(str(row["cost"]))

    fixed_costs = Decimal("0")
    for row in costs:
        cost_date = row.get("cost_date")
        if since_date and (not cost_date or cost_date < since_date):
            continue
        fixed_costs += Decimal(str(row["amount"]))

    return {
        "kmDriven": float(km),
        "flexibleCosts": float(flexible_costs),
        "fixedCosts": float(fixed_costs),
        "pricePerKm": price_per_km,
    }


def _personal_period_stats(
    user_id: str, trips: list, participants_by_trip: dict, costs: list, km_totals: dict,
    member_ids: list, since_date: str | None, price_per_km,
):
    """Same shape as _period_stats, but scoped to one member's own share -- their portion
    of km driven and trip cost (split the same way group balances are), plus their share
    of fixed costs using each cost's own participant snapshot and allocation method."""
    km = Decimal("0")
    flexible_costs = Decimal("0")
    for row in trips:
        participants = participants_by_trip.get(row["id"], [])
        if user_id not in participants:
            continue
        trip_date = row.get("trip_date")
        if since_date and (not trip_date or trip_date < since_date):
            continue
        if row.get("distance_km") is not None:
            km += Decimal(str(row["distance_km"])) / len(participants)
        if row.get("cost") is not None:
            flexible_costs += Decimal(str(row["cost"])) / len(participants)

    fixed_costs = Decimal("0")
    for row in costs:
        cost_date = row.get("cost_date")
        if since_date and (not cost_date or cost_date < since_date):
            continue
        participants = row.get("participants") or member_ids
        if user_id not in participants:
            continue

        amount = Decimal(str(row["amount"]))
        allocation_method = row.get("allocation_method") or "equal"
        if allocation_method == "per_km":
            weights = {pid: km_totals.get(pid, Decimal("0")) for pid in participants}
            total_weight = sum(weights.values())
            if total_weight > 0:
                fixed_costs += amount * weights.get(user_id, Decimal("0")) / total_weight
                continue
        fixed_costs += amount / len(participants)

    return {
        "kmDriven": float(km),
        "flexibleCosts": float(flexible_costs),
        "fixedCosts": float(fixed_costs),
        "pricePerKm": price_per_km,
    }


def _compute_trip_debt(trips: list, participants_by_trip: dict):
    """Each member's share of the (unreconciled) flexible/fuel cost of trips they were in.

    This has no matching credit yet -- it's what members owe for their car usage, to be
    reconciled against real fuel purchases once that flow exists. Not zero-sum by itself."""
    debt = {}
    for row in trips:
        cost = row.get("cost")
        if cost is None:
            continue
        participants = participants_by_trip.get(row["id"], [])
        if not participants:
            continue
        share = Decimal(str(cost)) / len(participants)
        for user_id in participants:
            debt[user_id] = debt.get(user_id, Decimal("0")) + share

    return debt


def _compute_trip_km_totals(trips: list, participants_by_trip: dict):
    """Each member's share of km driven, used to weight 'per_km' fixed-cost allocation.
    Mirrors _compute_trip_debt's split logic (a trip's distance is divided evenly among
    that trip's participants), just summing distance instead of cost."""
    km_totals = {}
    for row in trips:
        distance = row.get("distance_km")
        if distance is None:
            continue
        participants = participants_by_trip.get(row["id"], [])
        if not participants:
            continue
        share = Decimal(str(distance)) / len(participants)
        for user_id in participants:
            km_totals[user_id] = km_totals.get(user_id, Decimal("0")) + share

    return km_totals


def _compute_fixed_cost_shares(costs: list, member_ids: list, km_totals: dict):
    """Each member's share of every logged fixed cost, using that cost's own participant
    snapshot and allocation_method (not today's member list) -- so a member who joins
    later doesn't retroactively inherit a share of costs logged before they joined."""
    shares = {}
    for row in costs:
        amount = Decimal(str(row["amount"]))
        participants = row.get("participants") or member_ids
        if not participants:
            continue

        allocation_method = row.get("allocation_method") or "equal"
        if allocation_method == "per_km":
            weights = {pid: km_totals.get(pid, Decimal("0")) for pid in participants}
            total_weight = sum(weights.values())
            if total_weight > 0:
                for pid, weight in weights.items():
                    shares[pid] = shares.get(pid, Decimal("0")) + (amount * weight / total_weight)
                continue
            # No km logged yet for these participants -- fall back to an equal split.

        equal_share = amount / len(participants)
        for pid in participants:
            shares[pid] = shares.get(pid, Decimal("0")) + equal_share

    return shares


@bp.route("/api/groups/<group_id>/costs", methods=["GET"])
def list_costs(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        cost_rows = (
            client.table("costs")
            .select("id, category, paid_by, amount, cost_date, notes, logged_by, participants, allocation_method, photo_url, created_at")
            .eq("group_id", group_id)
            .order("cost_date", desc=True)
            .execute()
        )
        costs = cost_rows.data or []

        payer_ids = {row["paid_by"] for row in costs if row.get("paid_by")}
        profile_by_id = _get_profiles_by_id(client, payer_ids)

        serialized = [
            {
                "id": row["id"],
                "category": row.get("category"),
                "paidBy": row.get("paid_by"),
                "paidByName": _profile_name(profile_by_id.get(row.get("paid_by"), {})),
                "amount": row.get("amount"),
                "costDate": row.get("cost_date"),
                "notes": row.get("notes"),
                "participants": row.get("participants") or [],
                "allocationMethod": row.get("allocation_method") or "equal",
                "photoUrl": row.get("photo_url"),
                "createdAt": row.get("created_at"),
            }
            for row in costs
        ]

        total = sum((Decimal(str(row["amount"])) for row in costs), Decimal("0"))

        return jsonify({"costs": serialized, "summary": {"total": float(total)}}), 200

    except Exception as exc:
        logger.error(f"Failed to list costs for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't load costs right now. Please try again.")), 500


@bp.route("/api/groups/<group_id>/costs", methods=["POST"])
def create_cost(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else dict(request.form)
    body = body or {}
    photo = request.files.get("photo")

    field_errors = {}

    if request.is_json:
        requested_participant_ids = body.get("participantIds")
    else:
        requested_participant_ids = request.form.getlist("participantIds") or None

    category = str(body.get("category") or "").strip()
    if category not in ALLOWED_CATEGORIES:
        field_errors["category"] = f"Category must be one of {', '.join(ALLOWED_CATEGORIES)}"

    paid_by = str(body.get("paidBy") or "").strip()
    if not paid_by:
        field_errors["paidBy"] = "Select who paid"

    amount = _to_decimal(body.get("amount"))
    if amount is None or amount <= 0:
        field_errors["amount"] = "Enter a valid amount"

    cost_date_raw = str(body.get("costDate") or "").strip()
    cost_date_value = None
    if cost_date_raw:
        try:
            cost_date_value = datetime.strptime(cost_date_raw, "%Y-%m-%d").date()
        except ValueError:
            field_errors["costDate"] = "Enter a valid date"

    allocation_method = str(body.get("allocationMethod") or "equal").strip()
    if allocation_method not in ALLOCATION_METHODS:
        field_errors["allocationMethod"] = f"Allocation method must be one of {', '.join(ALLOCATION_METHODS)}"

    if requested_participant_ids is not None and not isinstance(requested_participant_ids, list):
        field_errors["participantIds"] = "Participants must be a list"
        requested_participant_ids = None

    if photo and not _is_supported_image(photo):
        field_errors["photo"] = "Only image uploads are allowed"

    if field_errors:
        return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": field_errors}), 400

    notes = str(body.get("notes") or "").strip() or None

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        member_ids = _get_group_members(client, group_id)
        if paid_by not in member_ids:
            return jsonify({
                "error": "Selected payer isn't a member of this group",
                "fieldErrors": {"paidBy": "Select a current group member"},
            }), 400

        # Snapshot the members this cost is split across at the moment it's logged, so
        # someone joining the group later doesn't retroactively inherit a share of it.
        if requested_participant_ids:
            participant_ids = [str(pid) for pid in requested_participant_ids if str(pid) in member_ids]
            if not participant_ids:
                return jsonify({
                    "error": "One or more selected participants aren't in this group",
                    "fieldErrors": {"participantIds": "Select only current group members"},
                }), 400
        else:
            participant_ids = member_ids

        photo_url = None
        if photo:
            photo_url, upload_error = _upload_cost_photo_to_storage(client, group_id, photo)
            if upload_error:
                return jsonify({"error": upload_error, "fieldErrors": {"photo": upload_error}}), 400

        cost_insert = {
            "group_id": group_id,
            "category": category,
            "paid_by": paid_by,
            "amount": float(amount),
            "logged_by": str(user.id),
            "notes": notes,
            "participants": participant_ids,
            "allocation_method": allocation_method,
            "photo_url": photo_url,
        }
        if cost_date_value:
            cost_insert["cost_date"] = cost_date_value.isoformat()

        result = client.table("costs").insert(cost_insert).execute()
        if not result.data:
            return jsonify(_friendly_error("We couldn't save this cost right now. Please retry.", can_retry=True)), 500

        return jsonify({"cost": result.data[0]}), 201

    except Exception as exc:
        logger.error(f"Failed to create cost for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't save this cost right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/costs/<cost_id>", methods=["PATCH"])
def edit_cost(group_id: str, cost_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    body = request.get_json(silent=True) if request.is_json else dict(request.form)
    body = body or {}
    photo = request.files.get("photo")

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        existing = (
            client.table("costs")
            .select("id")
            .eq("id", cost_id)
            .eq("group_id", group_id)
            .limit(1)
            .execute()
        )
        if not existing.data:
            return jsonify({"error": "Cost not found"}), 404

        updates = {}
        field_errors = {}

        if "category" in body:
            category = str(body.get("category") or "").strip()
            if category not in ALLOWED_CATEGORIES:
                field_errors["category"] = f"Category must be one of {', '.join(ALLOWED_CATEGORIES)}"
            else:
                updates["category"] = category

        if "amount" in body:
            amount = _to_decimal(body.get("amount"))
            if amount is None or amount <= 0:
                field_errors["amount"] = "Enter a valid amount"
            else:
                updates["amount"] = float(amount)

        if "costDate" in body:
            cost_date_raw = str(body.get("costDate") or "").strip()
            try:
                updates["cost_date"] = datetime.strptime(cost_date_raw, "%Y-%m-%d").date().isoformat()
            except ValueError:
                field_errors["costDate"] = "Enter a valid date"

        if "notes" in body:
            updates["notes"] = str(body.get("notes") or "").strip() or None

        if photo:
            if not _is_supported_image(photo):
                field_errors["photo"] = "Only image uploads are allowed"
            else:
                photo_url, upload_error = _upload_cost_photo_to_storage(client, group_id, photo)
                if upload_error:
                    field_errors["photo"] = upload_error
                else:
                    updates["photo_url"] = photo_url

        if field_errors:
            return jsonify({"error": "Please correct the highlighted fields", "fieldErrors": field_errors}), 400
        if not updates:
            return jsonify({"error": "No changes to save"}), 400

        result = client.table("costs").update(updates).eq("id", cost_id).execute()
        if not result.data:
            return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500

        return jsonify({"cost": result.data[0]}), 200

    except Exception as exc:
        logger.error(f"Failed to edit cost {cost_id} in group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't save your changes right now. Please retry.", can_retry=True)), 500


@bp.route("/api/groups/<group_id>/balances", methods=["GET"])
def get_balances(group_id: str):
    token, user, error = _auth_context()
    if error:
        return error

    try:
        client = db_for(token)
        if not _require_membership(client, group_id, str(user.id)):
            return jsonify({"error": "Group not found or access denied"}), 404

        member_ids = _get_group_members(client, group_id)
        profile_by_id = _get_profiles_by_id(client, member_ids)

        trips, participants_by_trip = _get_trips_with_participants(client, group_id)
        trip_debt = _compute_trip_debt(trips, participants_by_trip)
        km_totals = _compute_trip_km_totals(trips, participants_by_trip)

        cost_rows = (
            client.table("costs")
            .select("id, category, paid_by, amount, cost_date, notes, participants, allocation_method, created_at")
            .eq("group_id", group_id)
            .execute()
        )
        costs = cost_rows.data or []
        fixed_cost_shares = _compute_fixed_cost_shares(costs, member_ids, km_totals)

        paid_totals = {}
        for row in costs:
            payer = row.get("paid_by")
            paid_totals[payer] = paid_totals.get(payer, Decimal("0")) + Decimal(str(row["amount"]))

        balances = []
        for member_id in member_ids:
            paid = paid_totals.get(member_id, Decimal("0"))
            debt = trip_debt.get(member_id, Decimal("0"))
            fixed_share = fixed_cost_shares.get(member_id, Decimal("0"))
            balance = (paid - fixed_share - debt).quantize(Decimal("0.01"))
            balances.append({
                "userId": member_id,
                "name": _profile_name(profile_by_id.get(member_id, {})),
                "balance": float(balance),
            })

        activity = []
        for row in trips:
            participant_ids = participants_by_trip.get(row["id"], [])
            participant_names = [_profile_name(profile_by_id.get(pid, {})) for pid in participant_ids]
            details = f"{row.get('odometer_start')} → {row.get('odometer_end')} km"
            if row.get("notes"):
                details += f" · {row['notes']}"
            activity.append({
                "type": "trip",
                "date": row.get("trip_date"),
                "who": participant_names,
                "whoIds": participant_ids,
                "details": details,
                "amount": row.get("cost"),
                "createdAt": row.get("created_at"),
            })

        for row in costs:
            details = row.get("category") or ""
            if row.get("notes"):
                details += f" · {row['notes']}"
            activity.append({
                "type": "cost",
                "date": row.get("cost_date"),
                "who": [_profile_name(profile_by_id.get(row.get("paid_by"), {}))],
                "whoIds": [row.get("paid_by")],
                "details": details,
                "amount": row.get("amount"),
                "category": row.get("category"),
                "createdAt": row.get("created_at"),
            })

        activity.sort(key=lambda entry: (entry.get("date") or "", entry.get("createdAt") or ""), reverse=True)

        price_per_km = _get_group_price_per_km(client, group_id)
        month_start = date.today().replace(day=1).isoformat()
        requesting_user_id = str(user.id)

        return jsonify({
            "balances": balances,
            "activity": activity,
            "memberCount": len(member_ids),
            "summary": {
                "thisMonth": _period_stats(trips, costs, month_start, price_per_km),
                "allTime": _period_stats(trips, costs, None, price_per_km),
            },
            "personalSummary": {
                "thisMonth": _personal_period_stats(
                    requesting_user_id, trips, participants_by_trip, costs, km_totals,
                    member_ids, month_start, price_per_km
                ),
                "allTime": _personal_period_stats(
                    requesting_user_id, trips, participants_by_trip, costs, km_totals,
                    member_ids, None, price_per_km
                ),
                "balance": next((b["balance"] for b in balances if b["userId"] == requesting_user_id), 0.0),
            },
        }), 200

    except Exception as exc:
        logger.error(f"Failed to compute balances for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't load balances right now. Please try again.")), 500
