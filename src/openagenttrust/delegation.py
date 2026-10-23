"""Delegation chains: who granted an agent its authority, and how far it reaches.

A chain starts at a trust anchor (typically an organisation key) and ends at the agent
that made a request. Each link is signed by the previous link's subject, may only
narrow the scope (attenuation), and must be valid at the time of the request.
"""

from __future__ import annotations

import secrets
from collections.abc import Collection, Sequence
from datetime import datetime, timedelta
from typing import Any

from .canonical import digest
from .keys import SigningKey
from .models import Delegation, MalformedDocumentError, Scope, parse, to_document
from .signing import sign, verify
from .timeutil import format_ts, now_utc, parse_ts


class DelegationError(ValueError):
    """A delegation cannot be issued as requested."""


def pattern_matches(pattern: str, name: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def pattern_covers(parent: str, child: str) -> bool:
    """True if every name ``child`` matches is also matched by ``parent``."""
    if not parent.endswith("*"):
        return child == parent
    return child.removesuffix("*").startswith(parent[:-1])


def scope_covers(parent: Scope, child: Scope) -> bool:
    return all(any(pattern_covers(p, c) for p in parent.actions) for c in child.actions) and all(
        any(pattern_covers(p, c) for p in parent.resources) for c in child.resources
    )


def scope_permits(scope: Scope, action: str, resource: str) -> bool:
    return any(pattern_matches(p, action) for p in scope.actions) and any(
        pattern_matches(p, resource) for p in scope.resources
    )


def issue_delegation(
    issuer: SigningKey,
    subject: str,
    scope: Scope,
    *,
    expires_in: timedelta,
    may_delegate: bool = False,
    parent: dict[str, Any] | None = None,
    subject_name: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Issue a signed delegation from ``issuer`` to ``subject``.

    With ``parent``, the issuer re-delegates authority it was itself given: the parent's
    subject must be the issuer, the parent must allow re-delegation, the new scope must be
    within the parent's, and the new expiry is capped at the parent's.
    """
    start = now or now_utc()
    expires = start + expires_in
    parent_digest = None
    if parent is not None:
        parent_model = parse(Delegation, parent)
        if parent_model.subject != issuer.key_id:
            raise DelegationError("the parent delegation was not granted to this issuer")
        if not parent_model.may_delegate:
            raise DelegationError("the parent delegation does not allow re-delegation")
        if not scope_covers(parent_model.scope, scope):
            raise DelegationError("the requested scope exceeds the parent delegation")
        expires = min(expires, parse_ts(parent_model.expires_at))
        parent_digest = digest(parent)
    if expires <= start:
        raise DelegationError("the delegation would already be expired")
    document = to_document(
        Delegation(
            type="agentproof.delegation/v0.1",
            id="dlg_" + secrets.token_hex(12),
            issuer=issuer.key_id,
            subject=subject,
            subject_name=subject_name,
            scope=scope,
            may_delegate=may_delegate,
            not_before=format_ts(start),
            expires_at=format_ts(expires),
            parent=parent_digest,
            signature=None,
        )
    )
    return sign(document, issuer)


def chain_problems(
    chain: Sequence[Any],
    *,
    trust_anchors: Collection[str],
    agent: str,
    at: datetime,
) -> list[str]:
    """Everything wrong with ``chain`` as authority for ``agent`` at time ``at``."""
    if not chain:
        return ["the delegation chain is empty"]
    problems: list[str] = []
    links: list[Delegation] = []
    for index, document in enumerate(chain):
        try:
            links.append(parse(Delegation, document))
        except MalformedDocumentError as exc:
            return [f"link {index}: {exc}"]
    for index, (document, link) in enumerate(zip(chain, links, strict=True)):
        if not verify(document, link.issuer):
            problems.append(f"link {index}: signature is not valid for its issuer")
        if not parse_ts(link.not_before) <= at <= parse_ts(link.expires_at):
            problems.append(f"link {index}: not valid at {format_ts(at)}")
        if index == 0:
            if link.issuer not in trust_anchors:
                problems.append("link 0: issuer is not a trust anchor")
            if link.parent is not None:
                problems.append("link 0: a root delegation has no parent")
            continue
        previous = links[index - 1]
        if link.parent != digest(chain[index - 1]):
            problems.append(f"link {index}: parent digest does not match link {index - 1}")
        if link.issuer != previous.subject:
            problems.append(f"link {index}: issuer is not the subject of link {index - 1}")
        if not previous.may_delegate:
            problems.append(f"link {index - 1}: does not allow re-delegation")
        if not scope_covers(previous.scope, link.scope):
            problems.append(f"link {index}: scope exceeds link {index - 1}")
    if links[-1].subject != agent:
        problems.append("the last link was not granted to the requesting agent")
    return problems
