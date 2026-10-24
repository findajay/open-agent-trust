"""The enforcement point: authenticate, authorise, decide, execute, record.

A :class:`Gateway` sits between an agent and its tools. For every request it checks
the agent's signature and delegation chain, evaluates the policy, collects an approval
when the policy asks for one, runs the tool only if allowed, and issues a signed,
hash-chained receipt that anyone holding the right key ids can verify later.

Requests that fail authentication or delegation are rejected with
:class:`RequestRejected` and get no receipt: the gateway cannot attribute them. Every
authenticated, delegated request gets a receipt, including denials.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from pydantic import JsonValue

from .canonical import CanonicalizationError, digest
from .delegation import chain_problems, scope_permits
from .keys import SigningKey
from .ledger import Ledger
from .models import (
    ActionRequest,
    Approval,
    Delegation,
    MalformedDocumentError,
    ModelEvidence,
    Outcome,
    PolicyDecision,
    Receipt,
    parse,
    to_document,
)
from .policy import Policy
from .signing import sign, verify
from .timeutil import format_ts, now_utc, parse_ts
from .verify import approval_problems

Tool = Callable[[dict[str, JsonValue]], JsonValue]
Approver = Callable[[dict[str, Any], PolicyDecision], dict[str, Any] | None]


class RequestRejected(Exception):
    """The request could not be attributed or is outside the agent's delegated authority."""


@dataclass(frozen=True)
class ExecutionResult:
    receipt: dict[str, Any]
    result: JsonValue | None
    error: BaseException | None = None

    @property
    def status(self) -> str:
        return str(self.receipt["outcome"]["status"])

    @property
    def effect(self) -> str:
        return str(self.receipt["decision"]["effect"])


class Gateway:
    def __init__(
        self,
        key: SigningKey,
        policy: Policy,
        *,
        trust_anchors: Collection[str],
        ledger: Ledger | None = None,
        max_request_age: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] = now_utc,
    ) -> None:
        self.key = key
        self.policy = policy
        self.trust_anchors = frozenset(trust_anchors)
        # Not `ledger or Ledger()`: an empty ledger is falsy because it defines __len__.
        self.ledger = ledger if ledger is not None else Ledger()
        self.max_request_age = max_request_age
        self.clock = clock

    def _authenticate(
        self, request: dict[str, Any], delegation_chain: list[dict[str, Any]], now: datetime
    ) -> ActionRequest:
        try:
            model = parse(ActionRequest, request)
        except MalformedDocumentError as exc:
            raise RequestRejected(str(exc)) from exc
        if not verify(request, model.agent):
            raise RequestRejected("request signature is not valid for its agent")
        requested_at = parse_ts(model.requested_at)
        if requested_at < now - self.max_request_age or requested_at > now + timedelta(seconds=60):
            raise RequestRejected("request timestamp is outside the accepted window")
        if self.ledger.contains_request(digest(request)):
            raise RequestRejected("request was already processed (replay)")
        problems = chain_problems(
            delegation_chain,
            trust_anchors=self.trust_anchors,
            agent=model.agent,
            at=requested_at,
        )
        if problems:
            raise RequestRejected("delegation chain rejected: " + "; ".join(problems))
        for index, link in enumerate(delegation_chain):
            if not scope_permits(parse(Delegation, link).scope, model.action, model.resource):
                raise RequestRejected(
                    f"delegation link {index} does not permit {model.action} on {model.resource}"
                )
        return model

    def execute(
        self,
        request: dict[str, Any],
        delegation_chain: list[dict[str, Any]],
        tool: Tool,
        *,
        approver: Approver | None = None,
        model_evidence: list[dict[str, Any]] | None = None,
    ) -> ExecutionResult:
        now = self.clock()
        model = self._authenticate(request, delegation_chain, now)
        evidence = [parse(ModelEvidence, item) for item in model_evidence or []]
        request_digest = digest(request)
        decision = self.policy.evaluate(model.action, model.resource)

        approval: dict[str, Any] | None = None
        allowed = decision.effect == "allow"
        if decision.effect == "require_approval" and approver is not None:
            approval = approver(request, decision)
            if approval is not None:
                problems, approval_model = approval_problems(
                    approval, request_digest=request_digest, decision=decision
                )
                if problems or approval_model is None:
                    raise RequestRejected("approval rejected: " + "; ".join(problems))
                allowed = approval_model.decision == "approved"

        result: JsonValue | None = None
        error: BaseException | None = None
        if not allowed:
            outcome = Outcome(status="not_executed", result_digest=None, error_type=None)
        else:
            try:
                result = tool(model.arguments)
                outcome = Outcome(status="succeeded", result_digest=digest(result), error_type=None)
            except CanonicalizationError as exc:
                result, error = None, exc
                outcome = Outcome(status="failed", result_digest=None, error_type="InvalidResult")
            except Exception as exc:  # the tool's failure is recorded, not hidden
                result, error = None, exc
                outcome = Outcome(
                    status="failed", result_digest=None, error_type=type(exc).__name__[:256]
                )

        receipt = to_document(
            Receipt(
                type="agentproof.receipt/v0.1",
                id="rcp_" + secrets.token_hex(12),
                issuer=self.key.key_id,
                issued_at=format_ts(self.clock()),
                request=model,
                request_digest=request_digest,
                delegation_chain=[parse(Delegation, link) for link in delegation_chain],
                decision=decision,
                approval=parse(Approval, approval) if approval is not None else None,
                outcome=outcome,
                model_evidence=evidence,
                prev=self.ledger.head,
                signature=None,
            )
        )
        receipt = sign(receipt, self.key)
        self.ledger.append(receipt)
        return ExecutionResult(receipt=receipt, result=result, error=error)
