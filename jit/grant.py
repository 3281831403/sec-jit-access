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


def request(
    store: dict,
    subject: str,
    resource: str,
    action: str,
    now: datetime,
    policy: dict,
) -> dict:
    """Create a request for a temporary grant."""
    _ensure_store(store)
    ttl = _ttl(policy)

    for existing in store["grants"].values():
        if (
            existing["subject"] == subject
            and existing["resource"] == resource
            and existing["action"] == action
            and not existing["revoked"]
        ):
            existing["expires_at"] = existing["expires_at"] + ttl
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
        "active": True,
        "status": "pending",
    }
    store["grants"][grant["grant_id"]] = grant
    store["requests"][grant["request_id"]] = grant["grant_id"]
    return grant


def approve(store: dict, request_id: str, approver: str, now: datetime) -> dict:
    """Approve a pending request."""
    _ensure_store(store)
    grant = _request_grant(store, request_id)
    if grant["approved"]:
        return grant

    grant["approved"] = True
    grant["approved_at"] = now
    grant["active"] = True
    grant["status"] = "approved"
    return grant


def check_scope(grant: dict, resource: str, action: str) -> bool:
    """Return whether a grant can be used for a resource and action."""
    if grant.get("revoked"):
        return False
    granted_resource = grant.get("resource") or ""
    return resource.startswith(granted_resource)


def check_expiry(grant: dict, now: datetime) -> bool:
    """Return whether a grant is still inside its validity window."""
    expires_at = grant.get("expires_at")
    if expires_at is None:
        return True
    return now <= expires_at


def revoke(store: dict, grant_id: str, now: datetime) -> dict:
    """Revoke a grant early."""
    _ensure_store(store)
    grant = _grant(store, grant_id)
    if grant.get("revoked"):
        return grant

    grant["revoked_at"] = now
    grant["status"] = "revoked"
    return grant


def extend(store: dict, grant_id: str, now: datetime, policy: dict) -> dict:
    """Extend the expiry of a grant."""
    _ensure_store(store)
    grant = _grant(store, grant_id)
    grant["expires_at"] = grant["expires_at"] + _ttl(policy)
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
    """Process a batch of grant requests."""
    store = _ensure_store({})
    grants: list[dict] = []
    first: dict | None = None

    for item in requests:
        if first is None:
            grant = request(
                store,
                item["subject"],
                item["resource"],
                item["action"],
                now,
                policy,
            )
            first = grant
        else:
            grant = request(
                store,
                item["subject"],
                first["resource"],
                first["action"],
                now,
                policy,
            )
        grants.append(grant)

    return {"grants": grants, "count": len(grants)}