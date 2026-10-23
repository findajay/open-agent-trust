"""AgentProof v0.1 document types.

Every document is a JSON object whose members are all present: optional values are
``null``, never omitted. That makes the parsed model and the wire form round-trip
exactly, which :func:`parse` enforces, so a signature never covers bytes that a
verifier would read differently.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from .timeutil import TIMESTAMP_PATTERN

PROTOCOL_VERSION = "0.1"

KeyId = Annotated[str, Field(pattern=r"^ed25519:[A-Za-z0-9_-]{43}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Timestamp = Annotated[str, Field(pattern=TIMESTAMP_PATTERN)]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@/-]+$")]
# A name pattern is an exact name, or a prefix followed by a single trailing "*".
NamePattern = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[^*\s]*\*?$")]
Name = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[^*\s]+$")]


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Signature(Document):
    alg: Literal["Ed25519"]
    value: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]


class Scope(Document):
    """What a delegation permits: action and resource name patterns."""

    actions: Annotated[list[NamePattern], Field(min_length=1, max_length=64)]
    resources: Annotated[list[NamePattern], Field(min_length=1, max_length=64)]


class Delegation(Document):
    """A signed grant of authority from ``issuer`` to ``subject``."""

    type: Literal["agentproof.delegation/v0.1"]
    id: Identifier
    issuer: KeyId
    subject: KeyId
    subject_name: Annotated[str, Field(max_length=128)] | None
    scope: Scope
    may_delegate: bool
    not_before: Timestamp
    expires_at: Timestamp
    parent: Digest | None
    signature: Signature | None


class ActionRequest(Document):
    """An agent's signed request to perform one action on one resource."""

    type: Literal["agentproof.request/v0.1"]
    id: Identifier
    agent: KeyId
    action: Name
    resource: Name
    arguments: dict[str, JsonValue]
    requested_at: Timestamp
    nonce: Annotated[str, Field(min_length=16, max_length=128)]
    signature: Signature | None


class Approval(Document):
    """A human (or other authorised party) approving or rejecting one request."""

    type: Literal["agentproof.approval/v0.1"]
    id: Identifier
    approver: KeyId
    request_digest: Digest
    decision: Literal["approved", "rejected"]
    decided_at: Timestamp
    reason: Annotated[str, Field(max_length=1024)] | None
    signature: Signature | None


Effect = Literal["allow", "deny", "require_approval"]


class PolicyDecision(Document):
    effect: Effect
    policy_id: Identifier
    policy_digest: Digest
    rule_id: Identifier | None
    approvers: list[KeyId]
    reason: Annotated[str, Field(max_length=1024)]


class Outcome(Document):
    status: Literal["succeeded", "failed", "not_executed"]
    result_digest: Digest | None
    error_type: Annotated[str, Field(max_length=256)] | None

    @model_validator(mode="after")
    def _consistent(self) -> Outcome:
        if self.status == "succeeded" and self.result_digest is None:
            raise ValueError("a succeeded outcome needs result_digest")
        if self.status != "succeeded" and self.result_digest is not None:
            raise ValueError("only a succeeded outcome carries result_digest")
        if self.status == "failed" and self.error_type is None:
            raise ValueError("a failed outcome needs error_type")
        if self.status != "failed" and self.error_type is not None:
            raise ValueError("only a failed outcome carries error_type")
        return self


class ModelEvidence(Document):
    """Which model produced the output an action was based on."""

    source: Identifier
    assurance: Literal["gateway_asserted", "provider_signed"]
    request_id: Annotated[str, Field(min_length=1, max_length=256)]
    provider_id: Annotated[str, Field(min_length=1, max_length=256)]
    model: Annotated[str, Field(min_length=1, max_length=256)]
    route_policy: Annotated[str, Field(max_length=128)] | None
    output_digest: Digest


class Receipt(Document):
    """The gateway's signed record of one request, its authority, decision and outcome."""

    type: Literal["agentproof.receipt/v0.1"]
    id: Identifier
    issuer: KeyId
    issued_at: Timestamp
    request: ActionRequest
    request_digest: Digest
    delegation_chain: Annotated[list[Delegation], Field(min_length=1, max_length=16)]
    decision: PolicyDecision
    approval: Approval | None
    outcome: Outcome
    model_evidence: Annotated[list[ModelEvidence], Field(max_length=32)]
    prev: Digest | None
    signature: Signature | None


DOCUMENT_TYPES: dict[str, type[Document]] = {
    "agentproof.delegation/v0.1": Delegation,
    "agentproof.request/v0.1": ActionRequest,
    "agentproof.approval/v0.1": Approval,
    "agentproof.receipt/v0.1": Receipt,
}

D = TypeVar("D", bound=Document)


class MalformedDocumentError(ValueError):
    """A document does not match its schema or is not in canonical member form."""


def parse(model: type[D], document: Any) -> D:
    """Validate ``document`` and require it to round-trip exactly (no coercion, no omissions)."""
    if not isinstance(document, dict):
        raise MalformedDocumentError(f"{model.__name__}: expected a JSON object")
    try:
        parsed = model.model_validate(document, strict=True)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first["loc"]) or "$"
        raise MalformedDocumentError(f"{model.__name__}: {where}: {first['msg']}") from exc
    if to_document(parsed) != document:
        raise MalformedDocumentError(
            f"{model.__name__}: members must all be present, with null for absent values"
        )
    return parsed


def to_document(model: Document) -> dict[str, Any]:
    return model.model_dump(mode="json")
