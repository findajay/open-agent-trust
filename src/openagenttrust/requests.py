"""Agent-side and approver-side document builders."""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

from pydantic import JsonValue

from .canonical import canonical_bytes, digest
from .keys import SigningKey
from .models import ActionRequest, Approval, to_document
from .signing import sign
from .timeutil import format_ts, now_utc


def create_request(
    agent: SigningKey,
    action: str,
    resource: str,
    arguments: dict[str, JsonValue] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build and sign an action request as ``agent``."""
    arguments = arguments or {}
    canonical_bytes(arguments)  # fail early on values outside the canonical subset
    document = to_document(
        ActionRequest(
            type="agentproof.request/v0.1",
            id="req_" + secrets.token_hex(12),
            agent=agent.key_id,
            action=action,
            resource=resource,
            arguments=arguments,
            requested_at=format_ts(now or now_utc()),
            nonce=secrets.token_urlsafe(18),
            signature=None,
        )
    )
    return sign(document, agent)


def create_approval(
    approver: SigningKey,
    request: dict[str, Any],
    *,
    approved: bool = True,
    reason: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign an approval (or rejection) of exactly this request."""
    document = to_document(
        Approval(
            type="agentproof.approval/v0.1",
            id="apr_" + secrets.token_hex(12),
            approver=approver.key_id,
            request_digest=digest(request),
            decision="approved" if approved else "rejected",
            decided_at=format_ts(now or now_utc()),
            reason=reason,
            signature=None,
        )
    )
    return sign(document, approver)
