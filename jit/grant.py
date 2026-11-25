"""Temporary privilege grants with approval, scope, expiry, and revocation."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

__all__ = [
    "request",
    "approve",
    "check_scope",
    "check_expiry",
    "revoke",
    "extend",
    "validate_grant",
    "jit_batch",
]

_DEFAULT_TTL = timedelta(hours=1)


def _as_delta(value: Any, default: timedelta) -> timedelta:
    """Normalize a policy duration to a timedelta."""
    if value is None:
        return default
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    raise TypeError("policy duration must be a timedelta or a number of seconds")


def _ttl(policy: dict) -> timedelta:
    return _as_delta(policy.get("ttl"), _DEFAULT_TTL)


def _max_ttl(policy: dict) -> timedelta | None:
    """Return the policy ceiling on a grant's total lifetime, if any."""
    value = policy.get("max_ttl")
    if value is None:
        return None
    return _as_delta(value, _DEFAULT_TTL)


def _ensure_store(store: dict) -> dict:
    store.setdefault("grants", {})
    store.setdefault("requests", {})
    store.setdefault("seq", 0)
    return store


def _request_grant(store: dict, request_id: str) -> dict:
    grant_id = store["requests"].get(request_id)
    if grant_id is None:
        raise KeyError(f"unknown request: {request_id}")
    return store["grants"][grant_id]


def _grant(store: dict, grant_id: str) -> dict:
    try:
        return store["grants"][grant_id]
    except KeyError:
        raise KeyError(f"unknown grant: {grant_id}") from None


def _cap_for(grant: dict, policy: dict) -> datetime | None:
    """Hard ceiling on ``expires_at``: creation time plus the policy maximum."""
    cap_ttl = _max_ttl(policy)
    if cap_ttl is None:
        cap_ttl = grant.get("max_ttl")
    if cap_ttl is None:
        return None
    return grant["created_at"] + cap_ttl


def _capped(grant: dict, expires_at: datetime, policy: dict) -> datetime:
    cap = _cap_for(grant, policy)
    if cap is None:
        return expires_at
    return min(expires_at, cap)


def _is_expired(grant: dict, now: datetime) -> bool:
    expires_at = grant.get("expires_at")
    if expires_at is None:
        return True
    return now >= expires_at


def _mark_expired(grant: dict) -> None:
    """Lazily reclaim a grant that has reached its expiry instant."""
    grant["active"] = False
    grant["expired"] = True
    grant["status"] = "expired"


def _is_live(grant: dict, now: datetime) -> bool:
    """A grant is live when it has a future expiry and has not been revoked."""
    if grant.get("revoked"):
        return False
    expires_at = grant.get("expires_at")
    return expires_at is not None and now < expires_at


def request(
    store: dict,
    subject: str,
    resource: str,
    action: str,
    now: datetime,
    policy: dict,
) -> dict:
    """Create a request for a temporary grant.

    A request is only a request: it is not effective until approved.  Asking
    for the same permission again while a live grant exists returns that grant
    unchanged, so repeated requests never stack additional time.
    """
    _ensure_store(store)
    ttl = _ttl(policy)
    max_ttl = _max_ttl(policy)

    for existing in store["grants"].values():
        if (
            existing["subject"] == subject
            and existing["resource"] == resource
            and existing["action"] == action
            and _is_live(existing, now)
        ):
            return existing

    store["seq"] += 1
    number = store["seq"]
    grant = {
        "grant_id": f"g-{number}",
        "request_id": f"r-{number}",
        "subject": subject,
        "resource": resource,
        "action": action,
        "approved": False,
        "approver": None,
        "created_at": now,
        "approved_at": None,
        "expires_at": now + ttl,
        "revoked": False,
        "revoked_at": None,
        "expired": False,
        "active": False,
        "status": "pending",
        "ttl": ttl,
        "max_ttl": max_ttl,
    }
    grant["expires_at"] = _capped(grant, grant["expires_at"], policy)
    store["grants"][grant["grant_id"]] = grant
    store["requests"][grant["request_id"]] = grant["grant_id"]
    return grant


def approve(store: dict, request_id: str, approver: str, now: datetime) -> dict:
    """Approve a pending request, recording who approved it.

    Approval is idempotent: approving the same request again returns the same
    grant with the original approver, so repeated approvals cannot change the
    outcome.  Approval never resurrects a revoked or expired request.
    """
    _ensure_store(store)
    grant = _request_grant(store, request_id)

    if grant.get("revoked"):
        return grant
    if _is_expired(grant, now):
        # A request that already reached its expiry instant cannot be approved;
        # an already-approved grant is reclaimed rather than silently revived.
        _mark_expired(grant)
        return grant
    if grant.get("approved"):
        return grant
    if not approver:
        # An approval without a recorded approver is not an approval.
        return grant

    grant["approved"] = True
    grant["approver"] = approver
    grant["approved_at"] = now
    grant["active"] = True
    grant["status"] = "approved"
    return grant


def check_scope(
    grant: dict,
    resource: str,
    action: str,
    now: datetime | None = None,
) -> bool:
    """Return whether a grant can be used for a resource and action.

    The resource and the action must both match exactly; prefix or wildcard
    expansion is never allowed.  Unapproved, revoked, and expired grants are
    rejected.  Pass ``now`` to also enforce the validity window at call time.
    """
    if now is not None and not check_expiry(grant, now):
        return False
    if not grant.get("approved"):
        return False
    if grant.get("revoked") or grant.get("status") == "revoked":
        return False
    if grant.get("status") == "expired" or grant.get("expired"):
        return False
    if not grant.get("active", True):
        return False

    granted_resource = grant.get("resource")
    granted_action = grant.get("action")
    if not granted_resource or not granted_action:
        return False
    return granted_resource == resource and granted_action == action


def check_expiry(grant: dict, now: datetime) -> bool:
    """Return whether a grant is usable at ``now``.

    A grant is rejected from its expiry instant onwards, not just after it, and
    once rejected it is marked expired so that every later decision rejects it
    as well.
    """
    if not grant.get("approved"):
        return False
    if grant.get("revoked") or grant.get("status") == "revoked":
        return False
    if grant.get("status") == "expired" or grant.get("expired"):
        return False
    if _is_expired(grant, now):
        _mark_expired(grant)
        return False
    if not grant.get("active", True):
        return False
    return True


def revoke(store: dict, grant_id: str, now: datetime) -> dict:
    """Revoke a grant early; the revocation is effective immediately."""
    _ensure_store(store)
    grant = _grant(store, grant_id)
    if grant.get("revoked"):
        return grant

    grant["revoked"] = True
    grant["revoked_at"] = now
    grant["active"] = False
    grant["status"] = "revoked"
    return grant


def extend(store: dict, grant_id: str, now: datetime, policy: dict) -> dict:
    """Extend the expiry of a grant, never beyond the policy maximum.

    Revoked or expired grants are not resurrected, and the total lifetime can
    never exceed ``created_at + max_ttl``.
    """
    _ensure_store(store)
    grant = _grant(store, grant_id)

    if grant.get("revoked") or not grant.get("approved"):
        return grant
    if _is_expired(grant, now):
        _mark_expired(grant)
        return grant

    delta = _ttl(policy)
    if delta <= timedelta(0):
        return grant

    proposed = _capped(grant, grant["expires_at"] + delta, policy)
    if proposed > grant["expires_at"]:
        grant["expires_at"] = proposed
    return grant


def validate_grant(grant: dict) -> list[str]:
    """Return a list of problems found on a grant."""
    issues: list[str] = []
    if not grant.get("approver"):
        issues.append("missing_approver")
    if grant.get("expires_at") is None:
        issues.append("missing_expiry")

    resource = grant.get("resource") or ""
    action = grant.get("action") or ""
    broad_resource = (
        resource in {"", "/", "*"}
        or "*" in resource
        or "?" in resource
    )
    broad_action = action in {"", "*", "all"}
    if broad_resource or broad_action:
        issues.append("overbroad_scope")
    return issues


def jit_batch(requests: list[dict], policy: dict, now: datetime) -> dict:
    """Process a batch of grant requests.

    Every item is handled on its own fields and gets its own grant; one item's
    scope never leaks into another.
    """
    store = _ensure_store({})
    grants: list[dict] = []

    for item in requests:
        grant = request(
            store,
            item["subject"],
            item["resource"],
            item["action"],
            now,
            policy,
        )
        grants.append(grant)

    return {"grants": grants, "count": len(grants)}
