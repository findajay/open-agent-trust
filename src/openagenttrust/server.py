"""``oat serve``: an HTTP API in front of one gateway.

Agents (or the MCP proxy acting for them) submit signed requests and report outcomes;
people approve or reject pending requests; anyone with the token can browse and verify
the receipt ledger. The tool itself never runs here: the caller runs it after the
gateway allows it, then reports the result so the gateway can issue the receipt.

Endpoints (all JSON, all behind ``Authorization: Bearer <token>``)::

    GET  /v1/info                    gateway key, policy, trust anchors, ledger head
    POST /v1/actions                 {request, delegation_chain, model_evidence?}
    GET  /v1/actions/{id}?wait=SECS  status; long-polls while approval is pending
    POST /v1/actions/{id}/outcome    {result} or {error_type}
    GET  /v1/actions                 actions held in memory, newest first
    GET  /v1/approvals               actions awaiting approval
    POST /v1/approvals/{id}          {approval} (signed) or {decision, reason?}
    GET  /v1/receipts?limit&offset   newest first
    GET  /v1/receipts/{ref}          by agentproof:sha256:…, sha256:… or receipt id
    POST /v1/verify                  {receipt}
    GET  /v1/ledger                  JSON Lines, as `oat ledger verify` reads it
    GET  /v1/ledger/verify

Every action ends in exactly one receipt: denied and rejected requests at once, allowed
ones when the outcome is reported, and abandoned ones when their deadline passes
(not executed if still awaiting approval, failed with ``OutcomeNotReported`` if the
caller was allowed to run the tool but never said what happened).

Only stdlib HTTP is used, so the server adds no dependency. It binds to loopback by
default; put a TLS-terminating proxy in front of it before exposing it to a network.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sys
import threading
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .canonical import canonical_bytes
from .gateway import Authorization, Gateway, RequestRejected
from .keys import SigningKey
from .ledger import receipt_reference
from .models import to_document
from .requests import create_approval
from .timeutil import format_ts
from .verify import verify_ledger, verify_receipt

MAX_BODY_BYTES = 1 << 20
MAX_WAIT_SECONDS = 60.0


class ServiceError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Action:
    id: str
    auth: Authorization
    created_at: datetime
    deadline: datetime
    status: str  # pending_approval, allowed, denied, rejected, completed, expired
    receipt: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        request = self.auth.model
        leaf = self.auth.delegation_chain[-1] if self.auth.delegation_chain else {}
        references = request.arguments.get("references")
        return {
            "id": self.id,
            "status": self.status,
            "agent": request.agent,
            # The name the delegation gave the agent; informational, not signed by the agent.
            "agent_name": leaf.get("subject_name"),
            "action": request.action,
            "references": (
                [r for r in references if isinstance(r, str)]
                if isinstance(references, list)
                else []
            ),
            "resource": request.resource,
            "request": self.auth.request,
            "request_digest": self.auth.request_digest,
            "decision": to_document(self.auth.decision),
            "created_at": format_ts(self.created_at),
            "deadline": format_ts(self.deadline),
            "receipt_ref": receipt_reference(self.receipt) if self.receipt else None,
            "receipt": self.receipt,
        }


def _object(body: Any, member: str) -> dict[str, Any]:
    value = body.get(member) if isinstance(body, dict) else None
    if not isinstance(value, dict):
        raise ServiceError(HTTPStatus.BAD_REQUEST, f"'{member}' must be a JSON object")
    return value


class GatewayService:
    """The API's behaviour, independent of HTTP so it can be tested and embedded."""

    def __init__(
        self,
        gateway: Gateway,
        *,
        gateways: Collection[str] = (),
        approver_key: SigningKey | None = None,
        approval_timeout: timedelta = timedelta(minutes=10),
        outcome_timeout: timedelta = timedelta(minutes=10),
        retain: timedelta = timedelta(hours=1),
    ) -> None:
        self.gateway = gateway
        # Receipts this service verifies: its own, plus any others the operator trusts.
        self.gateways = frozenset([gateway.key.key_id, *gateways])
        self.approver_key = approver_key
        self.approval_timeout = approval_timeout
        self.outcome_timeout = outcome_timeout
        self.retain = retain
        self._actions: dict[str, Action] = {}
        self._changed = threading.Condition()

    # -- actions -------------------------------------------------------------------

    def submit(self, body: Any) -> dict[str, Any]:
        request = _object(body, "request")
        chain = body.get("delegation_chain")
        evidence = body.get("model_evidence") or []
        if not isinstance(chain, list) or not all(isinstance(link, dict) for link in chain):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "'delegation_chain' must be a list")
        if not isinstance(evidence, list) or not all(isinstance(e, dict) for e in evidence):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "'model_evidence' must be a list")
        try:
            auth = self.gateway.authorize(request, chain, model_evidence=evidence)
        except RequestRejected as exc:
            raise ServiceError(HTTPStatus.FORBIDDEN, str(exc)) from exc
        now = self.gateway.clock()
        action = Action(
            id="act_" + secrets.token_hex(12),
            auth=auth,
            created_at=now,
            deadline=now + self.outcome_timeout,
            status="allowed",
        )
        if auth.awaiting_approval:
            action.status, action.deadline = "pending_approval", now + self.approval_timeout
        elif not auth.allowed:
            action.status, action.receipt = "denied", self.gateway.complete(auth)
        with self._changed:
            self._actions[action.id] = action
            self._changed.notify_all()
        return action.to_dict()

    def _get(self, action_id: str) -> Action:
        action = self._actions.get(action_id)
        if action is None:
            raise ServiceError(HTTPStatus.NOT_FOUND, f"no action {action_id!r}")
        return action

    def action(self, action_id: str, *, wait: float = 0.0) -> dict[str, Any]:
        """The action's state; with ``wait``, block up to that long while it awaits approval."""
        wait = min(max(wait, 0.0), MAX_WAIT_SECONDS)
        with self._changed:
            action = self._get(action_id)
            if wait:
                self._changed.wait_for(lambda: action.status != "pending_approval", wait)
            return action.to_dict()

    def actions(self) -> list[dict[str, Any]]:
        """Actions still held in memory (receipted ones until ``retain``), newest first."""
        with self._changed:
            held = list(self._actions.values())
        return [a.to_dict() for a in sorted(held, key=lambda a: a.created_at, reverse=True)]

    def approvals(self) -> list[dict[str, Any]]:
        with self._changed:
            pending = [a for a in self._actions.values() if a.status == "pending_approval"]
        return [a.to_dict() for a in sorted(pending, key=lambda a: a.created_at)]

    def decide(self, action_id: str, body: Any) -> dict[str, Any]:
        """Attach an approval: a signed document, or a decision the server key signs."""
        if not isinstance(body, dict):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "expected a JSON object")
        with self._changed:
            action = self._get(action_id)
            if action.status != "pending_approval":
                raise ServiceError(HTTPStatus.CONFLICT, f"action is {action.status}")
            if "approval" in body:
                approval = _object(body, "approval")
            else:
                decision, reason = body.get("decision"), body.get("reason")
                if decision not in ("approved", "rejected"):
                    raise ServiceError(
                        HTTPStatus.BAD_REQUEST, "'decision' must be 'approved' or 'rejected'"
                    )
                if reason is not None and not isinstance(reason, str):
                    raise ServiceError(HTTPStatus.BAD_REQUEST, "'reason' must be a string")
                if self.approver_key is None:
                    raise ServiceError(
                        HTTPStatus.CONFLICT,
                        "this server has no approver key; send a signed 'approval' document",
                    )
                approval = create_approval(
                    self.approver_key,
                    action.auth.request,
                    approved=decision == "approved",
                    reason=reason,
                    now=self.gateway.clock(),
                )
            try:
                action.auth = self.gateway.attach_approval(action.auth, approval)
            except RequestRejected as exc:
                raise ServiceError(HTTPStatus.FORBIDDEN, str(exc)) from exc
            if action.auth.allowed:
                action.status = "allowed"
                action.deadline = self.gateway.clock() + self.outcome_timeout
            else:
                action.status, action.receipt = "rejected", self.gateway.complete(action.auth)
            self._changed.notify_all()
            return action.to_dict()

    def report_outcome(self, action_id: str, body: Any) -> dict[str, Any]:
        if not isinstance(body, dict) or ("result" in body) == ("error_type" in body):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "send exactly one of 'result', 'error_type'")
        error_type = body.get("error_type")
        if error_type is not None and not (isinstance(error_type, str) and error_type):
            raise ServiceError(HTTPStatus.BAD_REQUEST, "'error_type' must be a non-empty string")
        with self._changed:
            action = self._get(action_id)
            if action.status != "allowed":
                raise ServiceError(HTTPStatus.CONFLICT, f"action is {action.status}")
            action.receipt = self.gateway.complete(
                action.auth, result=body.get("result"), error_type=error_type
            )
            action.status = "completed"
            self._changed.notify_all()
            return action.to_dict()

    def sweep(self) -> None:
        """Receipt actions whose deadline passed, and forget finished ones after ``retain``."""
        now = self.gateway.clock()
        with self._changed:
            for action in list(self._actions.values()):
                if action.receipt is None and now >= action.deadline:
                    if action.status == "pending_approval":
                        action.receipt = self.gateway.complete(action.auth)
                    else:
                        action.receipt = self.gateway.complete(
                            action.auth, error_type="OutcomeNotReported"
                        )
                    action.status = "expired"
                    self._changed.notify_all()
                elif action.receipt is not None and now >= action.deadline + self.retain:
                    del self._actions[action.id]

    # -- ledger --------------------------------------------------------------------

    def info(self) -> dict[str, Any]:
        policy = self.gateway.policy
        return {
            "version": __version__,
            "gateway": self.gateway.key.key_id,
            "gateways": sorted(self.gateways),
            "trust_anchors": sorted(self.gateway.trust_anchors),
            "policy": {"id": policy.document.id, "digest": policy.digest},
            "approver": self.approver_key.key_id if self.approver_key else None,
            "ledger": {"length": len(self.gateway.ledger), "head": self.gateway.ledger.head},
        }

    def receipts(self, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        receipts = list(self.gateway.ledger)[::-1]
        page = receipts[max(offset, 0) : max(offset, 0) + min(max(limit, 1), 500)]
        return {
            "total": len(receipts),
            "receipts": [{"ref": receipt_reference(r), "receipt": r} for r in page],
        }

    def receipt(self, ref: str) -> dict[str, Any]:
        receipt = self.gateway.ledger.find(ref)
        if receipt is None:
            raise ServiceError(HTTPStatus.NOT_FOUND, f"no receipt {ref!r}")
        return {"ref": receipt_reference(receipt), "receipt": receipt}

    def verify(self, body: Any) -> dict[str, Any]:
        receipt = _object(body, "receipt")
        return verify_receipt(
            receipt,
            trust_anchors=self.gateway.trust_anchors,
            gateways=self.gateways,
            policy=self.gateway.policy,
        ).to_dict()

    def ledger_lines(self) -> str:
        """The ledger as JSON Lines, oldest first, in the form `oat ledger verify` reads."""
        return "".join(canonical_bytes(r).decode("utf-8") + "\n" for r in self.gateway.ledger)

    def verify_ledger(self) -> dict[str, Any]:
        return verify_ledger(
            self.gateway.ledger,
            trust_anchors=self.gateway.trust_anchors,
            gateways=self.gateways,
            policy=self.gateway.policy,
        ).to_dict()


_ROUTES: list[tuple[str, re.Pattern[str], str]] = [
    ("GET", re.compile(r"/v1/info"), "info"),
    ("GET", re.compile(r"/v1/actions"), "actions"),
    ("POST", re.compile(r"/v1/actions"), "submit"),
    ("GET", re.compile(r"/v1/actions/(?P<id>[\w-]+)"), "action"),
    ("POST", re.compile(r"/v1/actions/(?P<id>[\w-]+)/outcome"), "outcome"),
    ("GET", re.compile(r"/v1/approvals"), "approvals"),
    ("POST", re.compile(r"/v1/approvals/(?P<id>[\w-]+)"), "decide"),
    ("GET", re.compile(r"/v1/receipts"), "receipts"),
    ("GET", re.compile(r"/v1/receipts/(?P<ref>[\w:.@/-]+)"), "receipt"),
    ("POST", re.compile(r"/v1/verify"), "verify"),
    ("GET", re.compile(r"/v1/ledger"), "ledger"),
    ("GET", re.compile(r"/v1/ledger/verify"), "verify_ledger"),
]


class JsonLines(str):
    """A response body sent as ``application/x-ndjson`` instead of JSON."""


def _int(query: dict[str, list[str]], name: str, default: int) -> int:
    try:
        return int(query.get(name, [str(default)])[0])
    except ValueError as exc:
        raise ServiceError(HTTPStatus.BAD_REQUEST, f"'{name}' must be an integer") from exc


def _dispatch(
    service: GatewayService, name: str, params: dict[str, str], query: Any, body: Any
) -> Any:
    if name == "info":
        return service.info()
    if name == "actions":
        return {"actions": service.actions()}
    if name == "ledger":
        return JsonLines(service.ledger_lines())
    if name == "submit":
        return service.submit(body)
    if name == "action":
        try:
            wait = float(query.get("wait", ["0"])[0])
        except ValueError as exc:
            raise ServiceError(HTTPStatus.BAD_REQUEST, "'wait' must be a number") from exc
        return service.action(params["id"], wait=wait)
    if name == "outcome":
        return service.report_outcome(params["id"], body)
    if name == "approvals":
        return {"approvals": service.approvals()}
    if name == "decide":
        return service.decide(params["id"], body)
    if name == "receipts":
        return service.receipts(limit=_int(query, "limit", 50), offset=_int(query, "offset", 0))
    if name == "receipt":
        return service.receipt(params["ref"])
    if name == "verify":
        return service.verify(body)
    return service.verify_ledger()


def make_handler(
    service: GatewayService, *, token: str, cors_origin: str | None = None
) -> type[BaseHTTPRequestHandler]:
    expected = ("Bearer " + token).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"oat/{__version__}"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            sys.stderr.write(f"oat serve: {self.address_string()} {format % args}\n")

        def _send(self, status: HTTPStatus, payload: Any) -> None:
            if isinstance(payload, JsonLines):
                data, kind = payload.encode("utf-8"), "application/x-ndjson"
            else:
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                kind = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", f"{kind}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self._cors()
            self.end_headers()
            self.wfile.write(data)

        def _cors(self) -> None:
            if cors_origin and self.headers.get("Origin") == cors_origin:
                self.send_header("Access-Control-Allow-Origin", cors_origin)
                self.send_header("Vary", "Origin")

        def do_OPTIONS(self) -> None:
            self.send_response(HTTPStatus.NO_CONTENT)
            self._cors()
            if cors_origin and self.headers.get("Origin") == cors_origin:
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def _body(self) -> Any:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError as exc:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
            if length > MAX_BODY_BYTES:
                raise ServiceError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body too large")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return None
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ServiceError(HTTPStatus.BAD_REQUEST, "body is not valid JSON") from exc

        def _handle(self, method: str) -> None:
            try:
                given = self.headers.get("Authorization", "").encode("utf-8")
                if not hmac.compare_digest(given, expected):
                    raise ServiceError(HTTPStatus.UNAUTHORIZED, "missing or wrong bearer token")
                url = urlsplit(self.path)
                body = self._body() if method == "POST" else None
                for route_method, pattern, name in _ROUTES:
                    match = pattern.fullmatch(url.path)
                    if match and route_method == method:
                        payload = _dispatch(
                            service, name, match.groupdict(), parse_qs(url.query), body
                        )
                        self._send(HTTPStatus.OK, payload)
                        return
                raise ServiceError(HTTPStatus.NOT_FOUND, f"no route {method} {url.path}")
            except ServiceError as exc:
                self._send(exc.status, {"error": str(exc)})
            except Exception as exc:  # report, don't drop the connection
                self.log_error("internal error: %r", exc)
                self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    return Handler


def make_server(
    service: GatewayService,
    *,
    token: str,
    host: str = "127.0.0.1",
    port: int = 8787,
    cors_origin: str | None = None,
) -> ThreadingHTTPServer:
    if len(token) < 16:
        raise ValueError("the API token must be at least 16 characters")
    server = ThreadingHTTPServer(
        (host, port), make_handler(service, token=token, cors_origin=cors_origin)
    )
    server.daemon_threads = True
    return server


def serve(
    server: ThreadingHTTPServer, service: GatewayService, *, sweep_every: float = 5.0
) -> None:
    """Run until interrupted, expiring overdue actions in the background."""
    stop = threading.Event()

    def sweeper() -> None:
        while not stop.wait(sweep_every):
            service.sweep()

    thread = threading.Thread(target=sweeper, name="oat-sweeper", daemon=True)
    thread.start()
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()


__all__ = ["Action", "GatewayService", "ServiceError", "make_server", "serve"]
