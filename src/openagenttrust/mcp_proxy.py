"""``oat mcp-proxy``: enforce policy on MCP ``tools/call`` and receipt every call.

The proxy sits between an MCP client (Claude Code, an IDE, an agent framework) and one
MCP server over stdio. It starts the server as a subprocess and passes every message
through unchanged, except ``tools/call`` requests. For each of those it:

1. signs an AgentProof request as the agent: action ``mcp.<server>.<tool>``, resource
   the value of the configured resource argument (for example ``path``) or
   ``mcp:<server>``, arguments the tool arguments;
2. asks the gateway (in-process, or ``oat serve`` over HTTP) for a decision, waiting
   while a person approves when the policy requires it;
3. forwards the call only if allowed, and reports the server's answer so the gateway
   issues the receipt;
4. answers the client, with the receipt reference in the result's
   ``_meta["openagenttrust/receipt"]``. A blocked call gets a tool error result
   (``isError: true``) that explains why, so the model can see it and adapt.

Messages are newline-delimited JSON-RPC, as in the MCP stdio transport. Batches are
split and handled one message at a time, so a ``tools/call`` can't hide in a batch.
"""

from __future__ import annotations

import contextlib
import json
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import IO, Any, Protocol

from pydantic import JsonValue

from .canonical import CanonicalizationError, canonical_bytes
from .client import GatewayClient, GatewayClientError
from .gateway import Authorization, Gateway, RequestRejected
from .keys import SigningKey
from .ledger import receipt_reference
from .requests import create_request

META_KEY = "openagenttrust/receipt"
_NAME_LIMIT = 256


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    receipt: dict[str, Any] | None  # already issued when the call is not allowed
    handle: Any = None


class Authorizer(Protocol):
    def authorize(self, request: dict[str, Any], chain: list[dict[str, Any]]) -> Verdict:
        """Decide ``request``; raise :class:`RequestRejected` if it can't be attributed."""

    def finish(
        self, verdict: Verdict, *, result: JsonValue | None = None, error_type: str | None = None
    ) -> dict[str, Any]:
        """Report what happened to an allowed call and return its receipt."""


class LocalAuthorizer:
    """An in-process gateway. Calls that need approval are not executed: nobody can approve."""

    def __init__(self, gateway: Gateway) -> None:
        self.gateway = gateway

    def authorize(self, request: dict[str, Any], chain: list[dict[str, Any]]) -> Verdict:
        auth = self.gateway.authorize(request, chain)
        if auth.allowed:
            return Verdict(True, auth.decision.reason, None, auth)
        reason = auth.decision.reason
        if auth.awaiting_approval:
            reason += " (needs approval; run the gateway with `oat serve` to approve calls)"
        return Verdict(False, reason, self.gateway.complete(auth), auth)

    def finish(
        self, verdict: Verdict, *, result: JsonValue | None = None, error_type: str | None = None
    ) -> dict[str, Any]:
        auth: Authorization = verdict.handle
        return self.gateway.complete(auth, result=result, error_type=error_type)


class RemoteAuthorizer:
    """A gateway behind ``oat serve``, where people approve pending calls."""

    def __init__(
        self,
        client: GatewayClient,
        *,
        approval_wait: timedelta = timedelta(minutes=10),
        on_pending: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.client = client
        self.approval_wait = approval_wait
        self.on_pending = on_pending

    def authorize(self, request: dict[str, Any], chain: list[dict[str, Any]]) -> Verdict:
        try:
            action = self.client.submit(request, chain)
        except GatewayClientError as exc:
            if exc.status == 403:
                raise RequestRejected(exc.message) from exc
            raise
        if action["status"] == "pending_approval" and self.on_pending is not None:
            self.on_pending(action)
        give_up = time.monotonic() + self.approval_wait.total_seconds()
        while action["status"] == "pending_approval" and time.monotonic() < give_up:
            wait = min(30.0, max(give_up - time.monotonic(), 0.1))
            action = self.client.action(action["id"], wait=wait)
        reason = str(action["decision"]["reason"])
        if action["status"] == "allowed":
            return Verdict(True, reason, None, action["id"])
        if action["status"] == "pending_approval":
            reason += " (no approval arrived in time)"
        elif action["status"] in ("rejected", "expired"):
            reason += f" ({action['status']})"
        return Verdict(False, reason, action["receipt"], action["id"])

    def finish(
        self, verdict: Verdict, *, result: JsonValue | None = None, error_type: str | None = None
    ) -> dict[str, Any]:
        action = self.client.report_outcome(verdict.handle, result=result, error_type=error_type)
        return dict(action["receipt"])


def result_for_digest(result: Any) -> JsonValue:
    """What the receipt's ``result_digest`` covers for an MCP result.

    The result itself when it is in the canonical JSON subset; otherwise (MCP results may
    contain floats) its sorted, compact JSON text, which is a canonical string.
    """
    try:
        canonical_bytes(result)
        return result  # type: ignore[no-any-return]
    except CanonicalizationError:
        return json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _valid_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= _NAME_LIMIT
        and "*" not in value
        and not any(ch.isspace() for ch in value)
    )


class McpProxy:
    def __init__(
        self,
        upstream: Sequence[str],
        *,
        agent: SigningKey,
        delegation_chain: list[dict[str, Any]],
        authorizer: Authorizer,
        server_name: str,
        resource_argument: str | None = None,
        client_in: IO[bytes] | None = None,
        client_out: IO[bytes] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        if not upstream:
            raise ValueError("give the MCP server command to run")
        if not _valid_name(server_name) or "." in server_name:
            raise ValueError("the server name must be one word without dots or '*'")
        self.upstream = list(upstream)
        self.agent = agent
        self.delegation_chain = delegation_chain
        self.authorizer = authorizer
        self.server_name = server_name
        self.resource_argument = resource_argument
        self.client_in = client_in if client_in is not None else sys.stdin.buffer
        self.client_out = client_out if client_out is not None else sys.stdout.buffer
        self.log = log or (lambda line: sys.stderr.write(f"oat mcp-proxy: {line}\n"))
        self._write_lock = threading.Lock()
        self._upstream_lock = threading.Lock()
        self._waiting: dict[str, queue.Queue[dict[str, Any] | None]] = {}
        self._waiting_lock = threading.Lock()
        self._upstream_closed = False
        self._process: subprocess.Popen[bytes] | None = None

    # -- naming ----------------------------------------------------------------------

    def action_for(self, tool: str) -> str:
        return f"mcp.{self.server_name}.{tool}"

    def resource_for(self, arguments: dict[str, Any]) -> str:
        if self.resource_argument is not None:
            value = arguments.get(self.resource_argument)
            if _valid_name(value):
                return str(value)
        return f"mcp:{self.server_name}"

    # -- transport -------------------------------------------------------------------

    def _to_client(self, message: dict[str, Any]) -> None:
        data = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        with self._write_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def _to_upstream(self, message: Any) -> None:
        assert self._process is not None
        assert self._process.stdin is not None
        data = json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n"
        with self._upstream_lock:
            self._process.stdin.write(data)
            self._process.stdin.flush()

    def _read_upstream(self) -> None:
        assert self._process is not None
        assert self._process.stdout is not None
        for line in self._process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self.log("ignored a non-JSON line from the server")
                continue
            for item in message if isinstance(message, list) else [message]:
                if not isinstance(item, dict):
                    continue
                key = json.dumps(item.get("id")) if "id" in item else None
                is_response = "result" in item or "error" in item
                with self._waiting_lock:
                    waiter = self._waiting.pop(key, None) if key and is_response else None
                if waiter is not None:
                    waiter.put(item)
                else:
                    self._to_client(item)
        with self._waiting_lock:
            self._upstream_closed = True
            waiters, self._waiting = list(self._waiting.values()), {}
        for waiter in waiters:
            waiter.put(None)

    # -- tools/call ------------------------------------------------------------------

    def _blocked(self, message_id: Any, text: str, receipt: dict[str, Any] | None) -> None:
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": f"Blocked by OpenAgentTrust: {text}"}],
            "isError": True,
        }
        if receipt is not None:
            result["_meta"] = {META_KEY: receipt_reference(receipt)}
        self._to_client({"jsonrpc": "2.0", "id": message_id, "result": result})

    def handle_tool_call(self, message: dict[str, Any]) -> None:
        message_id = message.get("id")
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        tool = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool, str) or not _valid_name(tool) or not isinstance(arguments, dict):
            self._blocked(message_id, "the tool name or arguments are not acceptable", None)
            return
        action = self.action_for(tool)
        resource = self.resource_for(arguments)
        try:
            request = create_request(self.agent, action, resource, arguments)
            verdict = self.authorizer.authorize(request, self.delegation_chain)
        except CanonicalizationError as exc:
            self._blocked(message_id, f"arguments can't be signed: {exc}", None)
            return
        except RequestRejected as exc:
            self.log(f"rejected {action} on {resource}: {exc}")
            self._blocked(message_id, str(exc), None)
            return
        except Exception as exc:  # gateway unreachable: fail closed
            self.log(f"gateway error for {action} on {resource}: {exc}")
            self._blocked(message_id, f"the gateway could not be reached ({exc})", None)
            return

        if not verdict.allowed:
            ref = receipt_reference(verdict.receipt) if verdict.receipt else "no receipt"
            self.log(f"blocked {action} on {resource}: {verdict.reason} ({ref})")
            self._blocked(message_id, verdict.reason, verdict.receipt)
            return

        waiter: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=1)
        key = json.dumps(message_id)
        response: dict[str, Any] | None
        try:
            with self._waiting_lock:
                if self._upstream_closed:
                    raise BrokenPipeError("the MCP server exited")
                self._waiting[key] = waiter
            self._to_upstream(message)
            response = waiter.get()
        except OSError:
            with self._waiting_lock:
                self._waiting.pop(key, None)
            response = None

        if response is None:
            receipt = self.authorizer.finish(verdict, error_type="ServerClosed")
            self._to_client(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "error": {"code": -32603, "message": "the MCP server exited"},
                }
            )
        elif "error" in response:
            receipt = self.authorizer.finish(verdict, error_type="McpError")
            self._to_client(response)
        else:
            result = response.get("result")
            if isinstance(result, dict) and result.get("isError") is True:
                receipt = self.authorizer.finish(verdict, error_type="ToolError")
            else:
                receipt = self.authorizer.finish(verdict, result=result_for_digest(result))
            if isinstance(result, dict):
                meta = result.get("_meta")
                meta = meta if isinstance(meta, dict) else {}
                response = {
                    **response,
                    "result": {**result, "_meta": {**meta, META_KEY: receipt_reference(receipt)}},
                }
            self._to_client(response)
        self.log(
            f"{receipt['outcome']['status']} {action} on {resource} ({receipt_reference(receipt)})"
        )

    # -- main loop -------------------------------------------------------------------

    def run(self) -> int:
        self._process = subprocess.Popen(  # noqa: S603 - the operator's own server command
            self.upstream, stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        reader = threading.Thread(target=self._read_upstream, name="mcp-upstream", daemon=True)
        reader.start()
        workers: list[threading.Thread] = []
        for line in self.client_in:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._to_client(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                )
                continue
            for item in message if isinstance(message, list) else [message]:
                if isinstance(item, dict) and item.get("method") == "tools/call" and "id" in item:
                    worker = threading.Thread(
                        target=self.handle_tool_call, args=(item,), name="mcp-tool-call"
                    )
                    worker.start()
                    workers.append(worker)
                else:
                    try:
                        self._to_upstream(item)
                    except OSError:
                        self.log("the MCP server exited")
                        break
            workers = [w for w in workers if w.is_alive()]
        for worker in workers:
            worker.join()
        assert self._process.stdin is not None
        with contextlib.suppress(OSError):
            self._process.stdin.close()
        code = self._process.wait()
        reader.join(timeout=5)
        if self._process.stdout is not None:
            self._process.stdout.close()
        return code
