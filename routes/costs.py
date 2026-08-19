import logging
from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import Blueprint, jsonify, request

from supabase_client import db_for, get_token_from_request, get_user_from_token

bp = Blueprint("costs", __name__)
logger = logging.getLogger(__name__)

ALLOWED_CATEGORIES = ("Insurance", "Tax", "Depreciation")


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
        .select("id, odometer_reading, distance_km, cost, notes, trip_date, logged_by, created_at")
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
            .select("id, category, paid_by, amount, cost_date, notes, logged_by, created_at")
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

    body = request.get_json(silent=True) or {}

    field_errors = {}

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

        cost_insert = {
            "group_id": group_id,
            "category": category,
            "paid_by": paid_by,
            "amount": float(amount),
            "logged_by": str(user.id),
            "notes": notes,
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
        member_count = len(member_ids) or 1

        trips, participants_by_trip = _get_trips_with_participants(client, group_id)
        trip_debt = _compute_trip_debt(trips, participants_by_trip)

        cost_rows = (
            client.table("costs")
            .select("id, category, paid_by, amount, cost_date, notes, created_at")
            .eq("group_id", group_id)
            .execute()
        )
        costs = cost_rows.data or []
        total_fixed_costs = sum((Decimal(str(row["amount"])) for row in costs), Decimal("0"))
        equal_share = total_fixed_costs / member_count

        paid_totals = {}
        for row in costs:
            payer = row.get("paid_by")
            paid_totals[payer] = paid_totals.get(payer, Decimal("0")) + Decimal(str(row["amount"]))

        balances = []
        for member_id in member_ids:
            paid = paid_totals.get(member_id, Decimal("0"))
            debt = trip_debt.get(member_id, Decimal("0"))
            balance = (paid - equal_share - debt).quantize(Decimal("0.01"))
            balances.append({
                "userId": member_id,
                "name": _profile_name(profile_by_id.get(member_id, {})),
                "balance": float(balance),
            })

        activity = []
        for row in trips:
            participant_names = [
                _profile_name(profile_by_id.get(pid, {}))
                for pid in participants_by_trip.get(row["id"], [])
            ]
            details = f"{row.get('odometer_reading')} km"
            if row.get("notes"):
                details += f" · {row['notes']}"
            activity.append({
                "type": "trip",
                "date": row.get("trip_date"),
                "who": participant_names,
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
                "details": details,
                "amount": row.get("amount"),
                "category": row.get("category"),
                "createdAt": row.get("created_at"),
            })

        activity.sort(key=lambda entry: (entry.get("date") or "", entry.get("createdAt") or ""), reverse=True)

        return jsonify({
            "balances": balances,
            "activity": activity,
            "memberCount": len(member_ids),
        }), 200

    except Exception as exc:
        logger.error(f"Failed to compute balances for group {group_id}: {exc}")
        return jsonify(_friendly_error("We couldn't load balances right now. Please try again.")), 500
