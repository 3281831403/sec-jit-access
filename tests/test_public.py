from datetime import datetime, timedelta

from jit import (
    approve,
    check_expiry,
    check_scope,
    jit_batch,
    request,
    revoke,
)

T0 = datetime(2026, 11, 19, 9, 0, 0)
POLICY = {"ttl": timedelta(minutes=30), "max_ttl": timedelta(hours=2)}


def _store() -> dict:
    return {"grants": {}, "requests": {}, "seq": 0}


def test_request_and_approval_record_the_approver():
    store = _store()
    grant = request(
        store,
        "alice",
        "/warehouse/customers",
        "read",
        T0,
        POLICY,
    )

    assert grant["approved"] is False
    approved = approve(
        store,
        grant["request_id"],
        "oncall-lead",
        T0 + timedelta(minutes=2),
    )
    assert approved["approved"] is True
    assert approved["approver"] == "oncall-lead"


def test_scope_requires_exact_resource_and_action():
    store = _store()
    grant = request(
        store,
        "alice",
        "/warehouse/customers",
        "read",
        T0,
        POLICY,
    )
    approve(store, grant["request_id"], "oncall-lead", T0)

    assert check_scope(grant, "/warehouse/customers", "read") is True
    assert check_scope(grant, "/warehouse/customers-v2", "read") is False
    assert check_scope(grant, "/warehouse/customers", "write") is False


def test_grant_is_rejected_at_the_expiry_instant():
    store = _store()
    grant = request(
        store,
        "alice",
        "/warehouse/customers",
        "read",
        T0,
        POLICY,
    )
    approve(store, grant["request_id"], "oncall-lead", T0)

    assert check_expiry(grant, T0) is True
    assert check_expiry(grant, grant["expires_at"]) is False


def test_revoke_takes_effect_immediately():
    store = _store()
    grant = request(
        store,
        "alice",
        "/warehouse/customers",
        "read",
        T0,
        POLICY,
    )
    approve(store, grant["request_id"], "oncall-lead", T0)

    revoked = revoke(store, grant["grant_id"], T0 + timedelta(minutes=5))
    assert revoked["revoked"] is True
    assert check_scope(revoked, "/warehouse/customers", "read") is False


def test_batch_keeps_two_requests_independent():
    result = jit_batch(
        [
            {
                "subject": "alice",
                "resource": "/reports/q4",
                "action": "read",
            },
            {
                "subject": "bob",
                "resource": "/payroll/salaries",
                "action": "write",
            },
        ],
        POLICY,
        T0,
    )

    grants = result["grants"]
    assert len(grants) == 2
    assert grants[0]["resource"] == "/reports/q4"
    assert grants[1]["resource"] == "/payroll/salaries"
    assert grants[1]["action"] == "write"