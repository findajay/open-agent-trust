"""A small client for the ``oat serve`` HTTP API (stdlib only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlsplit

from pydantic import JsonValue


class GatewayClientError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class GatewayClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = 90.0) -> None:
        if urlsplit(base_url).scheme not in ("http", "https"):
            raise ValueError("the gateway URL must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.token = token
        # Longer than the server's longest long-poll, so a wait never times out locally.
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self.base_url + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                message = str(json.loads(exc.read()).get("error", exc.reason))
            except (json.JSONDecodeError, AttributeError):
                message = str(exc.reason)
            raise GatewayClientError(exc.code, message) from exc

    def info(self) -> dict[str, Any]:
        return dict(self._call("GET", "/v1/info"))

    def submit(
        self,
        request: dict[str, Any],
        delegation_chain: list[dict[str, Any]],
        model_evidence: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        body = {
            "request": request,
            "delegation_chain": delegation_chain,
            "model_evidence": model_evidence or [],
        }
        return dict(self._call("POST", "/v1/actions", body))

    def action(self, action_id: str, *, wait: float = 0.0) -> dict[str, Any]:
        return dict(self._call("GET", f"/v1/actions/{quote(action_id)}?wait={wait:g}"))

    def report_outcome(
        self, action_id: str, *, result: JsonValue | None = None, error_type: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"error_type": error_type} if error_type else {"result": result}
        return dict(self._call("POST", f"/v1/actions/{quote(action_id)}/outcome", body))

    def approvals(self) -> list[dict[str, Any]]:
        return list(self._call("GET", "/v1/approvals")["approvals"])

    def decide(
        self,
        action_id: str,
        *,
        approval: dict[str, Any] | None = None,
        approved: bool = True,
        reason: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = (
            {"approval": approval}
            if approval is not None
            else {"decision": "approved" if approved else "rejected", "reason": reason}
        )
        return dict(self._call("POST", f"/v1/approvals/{quote(action_id)}", body))

    def receipt(self, ref: str) -> dict[str, Any]:
        return dict(self._call("GET", f"/v1/receipts/{quote(ref, safe=':')}"))
