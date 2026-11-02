from __future__ import annotations

import io
import json
import sys
import threading
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from openagenttrust import (
    Gateway,
    Ledger,
    Policy,
    RequestRejected,
    Scope,
    SigningKey,
    create_approval,
    create_request,
    issue_delegation,
    verify_ledger,
    verify_receipt,
)
from openagenttrust.canonical import digest
from openagenttrust.client import GatewayClient, GatewayClientError
from openagenttrust.ledger import receipt_reference
from openagenttrust.mcp_proxy import (
    META_KEY,
    LocalAuthorizer,
    McpProxy,
    RemoteAuthorizer,
    result_for_digest,
)
from openagenttrust.server import GatewayService, ServiceError, make_server
from openagenttrust.timeutil import now_utc

from .conftest import NOW, World

FAKE_SERVER = [sys.executable, str(Path(__file__).with_name("fake_mcp_server.py"))]
TOKEN = "test-token-0123456789"


def request(world: World, action: str, **arguments: Any) -> dict[str, Any]:
    return create_request(world.agent, action, "plant-7/pump/P-3", {"n": 1, **arguments}, now=NOW)


def service_for(world: World, **kw: Any) -> GatewayService:
    return GatewayService(world.gateway, approver_key=world.approver, **kw)


def submit(service: GatewayService, world: World, action: str) -> dict[str, Any]:
    return service.submit({"request": request(world, action), "delegation_chain": world.chain})


def verified(world: World, receipt: dict[str, Any]) -> bool:
    return verify_receipt(receipt, **world.trust, policy=world.policy).ok


# -- gateway phases ----------------------------------------------------------------


def test_authorize_then_complete_issues_one_receipt(world: World) -> None:
    req = request(world, "sensor.read")
    auth = world.gateway.authorize(req, world.chain)
    assert auth.allowed
    assert not auth.awaiting_approval
    with pytest.raises(RequestRejected, match="replay"):
        world.gateway.authorize(req, world.chain)  # still in flight
    receipt = world.gateway.complete(auth, result={"ok": True})
    assert receipt["outcome"]["result_digest"] == digest({"ok": True})
    assert verified(world, receipt)
    with pytest.raises(RequestRejected, match="replay"):
        world.gateway.authorize(req, world.chain)


def test_release_lets_a_request_be_retried(world: World) -> None:
    req = request(world, "sensor.read")
    world.gateway.release(world.gateway.authorize(req, world.chain))
    assert world.gateway.authorize(req, world.chain).allowed


def test_complete_ignores_results_for_requests_that_are_not_allowed(world: World) -> None:
    auth = world.gateway.authorize(request(world, "pump.restart"), world.chain)
    assert auth.awaiting_approval
    assert not auth.allowed
    receipt = world.gateway.complete(auth, result="ran anyway")
    assert receipt["outcome"]["status"] == "not_executed"
    assert verified(world, receipt)


def test_attach_approval_only_when_awaiting(world: World) -> None:
    req = request(world, "sensor.read")
    auth = world.gateway.authorize(req, world.chain)
    with pytest.raises(RequestRejected, match="not awaiting"):
        world.gateway.attach_approval(auth, create_approval(world.approver, req, now=NOW))


# -- service -----------------------------------------------------------------------


def test_allowed_action_is_receipted_when_the_outcome_is_reported(world: World) -> None:
    service = service_for(world)
    action = submit(service, world, "sensor.read")
    assert (action["status"], action["receipt"]) == ("allowed", None)
    done = service.report_outcome(action["id"], {"result": {"bar": 3}})
    assert done["status"] == "completed"
    assert done["receipt_ref"] == receipt_reference(done["receipt"])
    assert verified(world, done["receipt"])
    with pytest.raises(ServiceError, match="completed"):
        service.report_outcome(action["id"], {"result": 1})


def test_actions_carry_agent_name_and_references(world: World) -> None:
    service = service_for(world)
    req = request(world, "sensor.read", references=["recall:memory:abc", 3])
    action = service.submit({"request": req, "delegation_chain": world.chain})
    assert action["agent_name"] == world.chain[-1]["subject_name"]
    assert action["references"] == ["recall:memory:abc"]
    assert [a["id"] for a in service.actions()] == [action["id"]]


def test_denied_action_is_receipted_at_once(world: World) -> None:
    action = submit(service_for(world), world, "logs.delete")
    assert action["status"] == "denied"
    assert action["receipt"]["outcome"]["status"] == "not_executed"


def test_rejected_and_unknown_requests(world: World) -> None:
    service = service_for(world)
    with pytest.raises(ServiceError) as info:
        service.submit({"request": request(world, "sensor.read"), "delegation_chain": []})
    assert info.value.status == 403
    with pytest.raises(ServiceError) as info:
        service.submit({"request": "nope"})
    assert info.value.status == 400
    with pytest.raises(ServiceError) as info:
        service.action("act_missing")
    assert info.value.status == 404


@pytest.mark.parametrize(
    ("decision", "status"), [("approved", "allowed"), ("rejected", "rejected")]
)
def test_server_signed_decision(world: World, decision: str, status: str) -> None:
    service = service_for(world)
    action = submit(service, world, "pump.restart")
    assert action["status"] == "pending_approval"
    assert [a["id"] for a in service.approvals()] == [action["id"]]
    decided = service.decide(action["id"], {"decision": decision, "reason": "checked on site"})
    assert decided["status"] == status
    assert service.approvals() == []
    if status == "allowed":
        decided = service.report_outcome(action["id"], {"result": "restarted"})
    receipt = decided["receipt"]
    assert receipt["approval"]["decision"] == decision
    assert receipt["approval"]["reason"] == "checked on site"
    assert verified(world, receipt)


def test_client_signed_approval_and_bad_approvals(world: World) -> None:
    service = GatewayService(world.gateway)  # no approver key
    action = submit(service, world, "pump.restart")
    with pytest.raises(ServiceError, match="no approver key"):
        service.decide(action["id"], {"decision": "approved"})
    impostor = SigningKey.generate()
    bad = create_approval(impostor, action["request"], now=NOW)
    with pytest.raises(ServiceError, match="not authorised"):
        service.decide(action["id"], {"approval": bad})
    good = create_approval(world.approver, action["request"], now=NOW)
    assert service.decide(action["id"], {"approval": good})["status"] == "allowed"


def test_long_poll_returns_when_approved(world: World) -> None:
    service = service_for(world)
    action = submit(service, world, "pump.restart")
    timer = threading.Timer(0.2, service.decide, (action["id"], {"decision": "approved"}))
    timer.start()
    started = time.monotonic()
    assert service.action(action["id"], wait=10)["status"] == "allowed"
    assert time.monotonic() - started < 5
    timer.join()


def test_sweep_receipts_abandoned_actions(world: World) -> None:
    clock = {"now": NOW}
    world.gateway.clock = lambda: clock["now"]
    service = service_for(
        world,
        approval_timeout=timedelta(minutes=1),
        outcome_timeout=timedelta(minutes=1),
        retain=timedelta(minutes=5),
    )
    pending = submit(service, world, "pump.restart")
    running = submit(service, world, "sensor.read")
    clock["now"] = NOW + timedelta(minutes=2)
    service.sweep()
    pending, running = service.action(pending["id"]), service.action(running["id"])
    assert (pending["status"], pending["receipt"]["outcome"]["status"]) == (
        "expired",
        "not_executed",
    )
    assert running["receipt"]["outcome"] == {
        "status": "failed",
        "result_digest": None,
        "error_type": "OutcomeNotReported",
    }
    assert verify_ledger(world.gateway.ledger, **world.trust, policy=world.policy).ok
    clock["now"] = NOW + timedelta(minutes=10)
    service.sweep()
    with pytest.raises(ServiceError):
        service.action(running["id"])


def test_receipts_listing_lookup_and_verification(world: World) -> None:
    service = service_for(world)
    first = submit(service, world, "logs.delete")["receipt"]
    second = submit(service, world, "logs.delete")["receipt"]
    listing = service.receipts(limit=1)
    assert listing["total"] == 2
    assert listing["receipts"][0]["receipt"] == second
    ref = receipt_reference(first)
    assert service.receipt(ref)["receipt"] == first
    assert service.receipt(ref.removeprefix("agentproof:"))["receipt"] == first
    assert service.receipt(first["id"])["receipt"] == first
    assert service.verify({"receipt": first})["ok"]
    assert service.verify_ledger()["ok"]
    tampered = {**first, "issued_at": "2026-10-23T12:00:01Z"}
    assert not service.verify({"receipt": tampered})["ok"]
    info = service.info()
    assert info["ledger"] == {"length": 2, "head": digest(second)}
    assert info["approver"] == world.approver.key_id


# -- HTTP --------------------------------------------------------------------------


@pytest.fixture
def http(world: World) -> Iterator[tuple[GatewayService, GatewayClient]]:
    service = service_for(world)
    server = make_server(service, token=TOKEN, port=0, cors_origin="http://localhost:5173")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield service, GatewayClient(f"http://{host!s}:{port}", TOKEN)
    server.shutdown()
    server.server_close()


def test_http_round_trip(world: World, http: tuple[GatewayService, GatewayClient]) -> None:
    _, client = http
    assert client.info()["gateway"] == world.gateway_key.key_id
    action = client.submit(request(world, "pump.restart"), world.chain)
    assert [a["id"] for a in client.approvals()] == [action["id"]]
    assert client.decide(action["id"], approved=True)["status"] == "allowed"
    done = client.report_outcome(action["id"], result={"ok": True})
    assert verified(world, done["receipt"])
    assert client.receipt(done["receipt_ref"])["receipt"] == done["receipt"]
    [held] = client.actions()
    assert (held["id"], held["status"], held["references"]) == (action["id"], "completed", [])
    lines = client.ledger().splitlines()
    assert [json.loads(line) for line in lines] == [done["receipt"]]


def test_http_errors(world: World, http: tuple[GatewayService, GatewayClient]) -> None:
    _, client = http
    with pytest.raises(GatewayClientError) as info:
        GatewayClient(client.base_url, "wrong-token-0123456789").info()
    assert info.value.status == 401
    with pytest.raises(GatewayClientError) as info:
        client.action("act_missing")
    assert info.value.status == 404
    with pytest.raises(GatewayClientError) as info:
        client.submit(request(world, "sensor.read"), [])
    assert info.value.status == 403
    with pytest.raises(ValueError, match="http"):
        GatewayClient("file:///etc/passwd", TOKEN)


def test_short_tokens_are_refused(world: World) -> None:
    with pytest.raises(ValueError, match="16 characters"):
        make_server(service_for(world), token="short", port=0)


# -- MCP proxy ---------------------------------------------------------------------


def mcp_world(tmp_path: Path) -> tuple[SigningKey, list[dict[str, Any]], Gateway, SigningKey]:
    org, agent, approver, gateway_key = (SigningKey.generate() for _ in range(4))
    chain = [
        issue_delegation(
            org,
            agent.key_id,
            Scope(actions=["mcp.fs.*"], resources=["*"]),
            expires_in=timedelta(hours=1),
        )
    ]
    policy = Policy.from_mapping(
        {
            "id": "mcp-test@1",
            "rules": [
                {
                    "id": "read",
                    "effect": "allow",
                    "actions": ["mcp.fs.read_file", "mcp.fs.explode"],
                },
                {
                    "id": "write",
                    "effect": "require_approval",
                    "actions": ["mcp.fs.write_file"],
                    "approvers": [approver.key_id],
                },
                {"id": "no-delete", "effect": "deny", "actions": ["mcp.fs.delete_file"]},
            ],
        }
    )
    gateway = Gateway(
        gateway_key, policy, trust_anchors=[org.key_id], ledger=Ledger(tmp_path / "ledger.jsonl")
    )
    return agent, chain, gateway, approver


def call(message_id: int, tool: str, **arguments: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def run_proxy(proxy_kwargs: dict[str, Any], messages: list[Any]) -> dict[Any, dict[str, Any]]:
    client_in = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in messages))
    client_out = io.BytesIO()
    proxy = McpProxy(
        FAKE_SERVER,
        server_name="fs",
        resource_argument="path",
        client_in=client_in,
        client_out=client_out,
        log=lambda line: None,
        **proxy_kwargs,
    )
    assert proxy.run() == 0
    replies = [json.loads(line) for line in client_out.getvalue().splitlines()]
    return {r["id"]: r for r in replies}


def test_mcp_proxy_enforces_and_receipts_tool_calls(tmp_path: Path) -> None:
    agent, chain, gateway, _ = mcp_world(tmp_path)
    replies = run_proxy(
        {"agent": agent, "delegation_chain": chain, "authorizer": LocalAuthorizer(gateway)},
        [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            call(2, "read_file", path="docs/readme.md"),
            [call(3, "delete_file", path="docs/readme.md")],  # batches are split, not smuggled
            call(4, "write_file", path="src/app.py", text="x"),
            call(5, "explode"),
        ],
    )
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["read_file", "write_file"]

    allowed = replies[2]["result"]
    assert allowed["content"][0]["text"].startswith("read_file")
    assert allowed["structuredContent"] == {"score": 0.5}
    denied, needs_approval, tool_error = (replies[i]["result"] for i in (3, 4, 5))
    assert denied["isError"]
    assert "Blocked by OpenAgentTrust" in denied["content"][0]["text"]
    assert needs_approval["isError"]
    assert "needs approval" in needs_approval["content"][0]["text"]
    assert tool_error["content"][0]["text"] == "boom"

    receipts = {r["request"]["action"]: r for r in Ledger(tmp_path / "ledger.jsonl")}
    assert len(receipts) == 4
    read = receipts["mcp.fs.read_file"]
    assert read["request"]["resource"] == "docs/readme.md"
    assert read["outcome"]["status"] == "succeeded"
    upstream_result = {k: v for k, v in allowed.items() if k != "_meta"}
    assert read["outcome"]["result_digest"] == digest(result_for_digest(upstream_result))
    assert allowed["_meta"][META_KEY] == receipt_reference(read)
    assert denied["_meta"][META_KEY] == receipt_reference(receipts["mcp.fs.delete_file"])
    assert receipts["mcp.fs.write_file"]["outcome"]["status"] == "not_executed"
    assert receipts["mcp.fs.explode"]["outcome"]["error_type"] == "ToolError"
    assert receipts["mcp.fs.explode"]["request"]["resource"] == "mcp:fs"
    trust = {"trust_anchors": list(gateway.trust_anchors), "gateways": [gateway.key.key_id]}
    assert verify_ledger(receipts.values(), **trust, policy=gateway.policy).ok


def test_mcp_proxy_waits_for_approval_through_the_server(tmp_path: Path) -> None:
    agent, chain, gateway, approver = mcp_world(tmp_path)
    service = GatewayService(gateway, approver_key=approver)
    server = make_server(service, token=TOKEN, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    client = GatewayClient(f"http://{host!s}:{port}", TOKEN)

    def approve_when_pending() -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            for action in client.approvals():
                client.decide(action["id"], approved=True, reason="looks fine")
                return
            time.sleep(0.05)

    approver_thread = threading.Thread(target=approve_when_pending)
    approver_thread.start()
    try:
        replies = run_proxy(
            {
                "agent": agent,
                "delegation_chain": chain,
                "authorizer": RemoteAuthorizer(client, approval_wait=timedelta(seconds=20)),
            },
            [call(1, "write_file", path="src/app.py", text="x"), call(2, "delete_file")],
        )
        written = replies[1]["result"]
        assert not written.get("isError")
        receipt = client.receipt(written["_meta"][META_KEY])["receipt"]
    finally:
        approver_thread.join()
        server.shutdown()
        server.server_close()

    assert receipt["approval"]["reason"] == "looks fine"
    assert receipt["outcome"]["status"] == "succeeded"
    assert replies[2]["result"]["isError"]
    assert service.verify_ledger()["ok"]


def test_mcp_proxy_fails_closed_when_the_gateway_is_unreachable(tmp_path: Path) -> None:
    agent, chain, _, _ = mcp_world(tmp_path)
    client = GatewayClient("http://127.0.0.1:9", TOKEN, timeout=2)
    replies = run_proxy(
        {"agent": agent, "delegation_chain": chain, "authorizer": RemoteAuthorizer(client)},
        [call(1, "read_file", path="a")],
    )
    assert "could not be reached" in replies[1]["result"]["content"][0]["text"]


def test_mcp_proxy_validates_its_configuration(tmp_path: Path) -> None:
    agent, chain, gateway, _ = mcp_world(tmp_path)
    with pytest.raises(ValueError, match="server name"):
        McpProxy(
            FAKE_SERVER,
            agent=agent,
            delegation_chain=chain,
            authorizer=LocalAuthorizer(gateway),
            server_name="a.b",
        )
    assert isinstance(now_utc(), datetime)
