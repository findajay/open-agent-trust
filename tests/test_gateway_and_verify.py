from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any

import pytest

from openagenttrust import (
    Policy,
    RequestRejected,
    SigningKey,
    create_approval,
    create_request,
    verify_ledger,
    verify_receipt,
)
from openagenttrust.signing import sign

from .conftest import NOW, World, make_policy


def ok_tool(args: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "echo": args}


def check(world: World, receipt: dict[str, Any], policy: Policy | None = None) -> dict[str, str]:
    report = verify_receipt(receipt, **world.trust, policy=policy or world.policy)
    return {c.name: c.status for c in report.checks}


def request(
    world: World, action: str, resource: str = "plant-7/pump/P-3", **kw: Any
) -> dict[str, Any]:
    return create_request(world.agent, action, resource, {"n": 1}, now=kw.pop("now", NOW))


def approve(world: World, *, approved: bool = True, key: SigningKey | None = None):  # type: ignore[no-untyped-def]
    return lambda req, decision: create_approval(
        key or world.approver, req, approved=approved, now=NOW
    )


def test_allowed_action_executes_and_verifies(world: World) -> None:
    result = world.gateway.execute(request(world, "sensor.read"), world.chain, ok_tool)
    assert (result.effect, result.status) == ("allow", "succeeded")
    assert result.result == {"ok": True, "echo": {"n": 1}}
    statuses = check(world, result.receipt)
    assert set(statuses.values()) == {"pass", "skip"}
    assert statuses["approval"] == "skip"


def test_denied_action_is_not_executed_but_is_receipted(world: World) -> None:
    called = []
    result = world.gateway.execute(
        request(world, "logs.delete"), world.chain, lambda a: called.append(a)
    )
    assert (result.effect, result.status, called) == ("deny", "not_executed", [])
    assert verify_receipt(result.receipt, **world.trust, policy=world.policy).ok


def test_approval_flow(world: World) -> None:
    approved = world.gateway.execute(
        request(world, "pump.restart"), world.chain, ok_tool, approver=approve(world)
    )
    assert approved.status == "succeeded"
    assert check(world, approved.receipt)["approval"] == "pass"

    rejected = world.gateway.execute(
        request(world, "pump.restart"),
        world.chain,
        ok_tool,
        approver=approve(world, approved=False),
    )
    assert rejected.status == "not_executed"

    no_approver = world.gateway.execute(request(world, "pump.restart"), world.chain, ok_tool)
    assert no_approver.status == "not_executed"
    assert verify_ledger(world.gateway.ledger, **world.trust, policy=world.policy).ok


def test_approval_from_an_unlisted_key_is_rejected(world: World) -> None:
    with pytest.raises(RequestRejected, match="not authorised"):
        world.gateway.execute(
            request(world, "pump.restart"),
            world.chain,
            ok_tool,
            approver=approve(world, key=world.agent),
        )


def test_tool_failure_is_recorded(world: World) -> None:
    def broken(_: dict[str, Any]) -> None:
        raise TimeoutError("pump controller did not answer")

    result = world.gateway.execute(request(world, "sensor.read"), world.chain, broken)
    assert result.status == "failed"
    assert result.receipt["outcome"]["error_type"] == "TimeoutError"
    assert isinstance(result.error, TimeoutError)
    assert verify_receipt(result.receipt, **world.trust).ok


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda w, r: {**r, "action": "sensor.write"}, "signature"),
        (
            lambda w, r: create_request(SigningKey.generate(), "sensor.read", "plant-7/x", now=NOW),
            "requesting agent",
        ),
        (
            lambda w, r: create_request(w.agent, "sensor.read", "plant-9/x", now=NOW),
            "does not permit",
        ),
        (
            lambda w, r: create_request(
                w.agent, "sensor.read", "plant-7/x", now=NOW - timedelta(hours=1)
            ),
            "window",
        ),
        (lambda w, r: {**r, "extra": 1}, "Extra"),
    ],
)
def test_unattributable_or_unauthorised_requests_are_rejected(
    world: World, mutate, message
) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RequestRejected, match=message):
        world.gateway.execute(mutate(world, request(world, "sensor.read")), world.chain, ok_tool)
    assert len(world.gateway.ledger) == 0


def test_replayed_request_is_rejected(world: World) -> None:
    req = request(world, "sensor.read")
    world.gateway.execute(req, world.chain, ok_tool)
    with pytest.raises(RequestRejected, match="replay"):
        world.gateway.execute(req, world.chain, ok_tool)


@pytest.fixture
def approved_receipt(world: World) -> dict[str, Any]:
    return world.gateway.execute(
        request(world, "pump.restart"), world.chain, ok_tool, approver=approve(world)
    ).receipt


def _resign(world: World, receipt: dict[str, Any]) -> dict[str, Any]:
    return sign(receipt, world.gateway_key)


@pytest.mark.parametrize(
    ("tamper", "failing"),
    [
        (lambda w, r: r.update(issued_at="2026-10-23T12:00:01Z"), {"gateway-signature"}),
        (
            lambda w, r: r["request"].update(resource="plant-7/pump/P-4"),
            {"gateway-signature", "request-digest", "agent-signature"},
        ),
        (
            lambda w, r: r.update(issuer=SigningKey.generate().key_id),
            {"gateway-trusted", "gateway-signature"},
        ),
    ],
)
def test_tampering_is_detected(world: World, approved_receipt, tamper, failing) -> None:  # type: ignore[no-untyped-def]
    receipt = copy.deepcopy(approved_receipt)
    tamper(world, receipt)
    statuses = check(world, receipt)
    assert {name for name, status in statuses.items() if status == "fail"} == failing


def test_a_compromised_gateway_cannot_fake_an_approval(world: World, approved_receipt) -> None:  # type: ignore[no-untyped-def]
    """Even re-signed by the trusted gateway, a receipt can't claim enforcement it didn't do."""
    no_approval = _resign(world, {**approved_receipt, "approval": None})
    assert check(world, no_approval)["enforcement"] == "fail"

    forged = copy.deepcopy(approved_receipt)
    forged["approval"]["approver"] = world.gateway_key.key_id
    assert check(world, _resign(world, forged))["approval"] == "fail"

    flipped = copy.deepcopy(approved_receipt)
    flipped["decision"]["effect"] = "allow"
    flipped["decision"]["approvers"] = []
    statuses = check(world, _resign(world, flipped))
    assert statuses["policy-decision"] == "fail"


def test_receipt_under_a_different_policy_is_flagged(world: World, approved_receipt) -> None:  # type: ignore[no-untyped-def]
    other = make_policy(SigningKey.generate())
    assert check(world, approved_receipt, policy=other)["policy-decision"] == "fail"


def test_malformed_receipt(world: World) -> None:
    report = verify_receipt({"type": "agentproof.receipt/v0.1"}, **world.trust)
    assert [c.name for c in report.failures] == ["structure"]


def test_ledger_detects_removed_and_reordered_receipts(world: World) -> None:
    for _ in range(3):
        world.gateway.execute(request(world, "sensor.read"), world.chain, ok_tool)
    receipts = list(world.gateway.ledger)
    assert verify_ledger(receipts, **world.trust).ok
    assert not verify_ledger([receipts[0], receipts[2]], **world.trust).ok
    assert not verify_ledger([receipts[1], receipts[0], receipts[2]], **world.trust).ok
