"""The enforcement point: authenticate, authorise, decide, execute, record.

A :class:`Gateway` sits between an agent and its tools. For every request it checks
the agent's signature and delegation chain, evaluates the policy, collects an approval
when the policy asks for one, runs the tool only if allowed, and issues a signed,
hash-chained receipt that anyone holding the right key ids can verify later.

Requests that fail authentication or delegation are rejected with
:class:`RequestRejected` and get no receipt: the gateway cannot attribute them. Every
authenticated, delegated request gets a receipt, including denials.

:meth:`Gateway.execute` does all of this in one call. When the tool runs elsewhere (an
MCP proxy, a remote client) or the approval arrives later (a person in the Studio), use
the two phases directly: :meth:`Gateway.authorize`, then :meth:`Gateway.complete`.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable, Collection
from dataclasses import dataclass, replace
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
class Authorization:
    """A request that passed authentication and has a policy decision, but no receipt yet.

    Every authorization ends in exactly one receipt: pass it to :meth:`Gateway.complete`
    after running the tool (or instead of running it, when ``allowed`` is false).
    """

    request: dict[str, Any]
    model: ActionRequest
    request_digest: str
    delegation_chain: list[dict[str, Any]]
    decision: PolicyDecision
    model_evidence: list[ModelEvidence]
    approval: dict[str, Any] | None = None

    @property
    def awaiting_approval(self) -> bool:
        return self.decision.effect == "require_approval" and self.approval is None

    @property
    def allowed(self) -> bool:
        if self.decision.effect == "allow":
            return True
        if self.decision.effect == "require_approval" and self.approval is not None:
            return str(self.approval["decision"]) == "approved"
        return False


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
        # Requests authorized but not yet receipted, so a replay can't slip in between.
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()

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

    def authorize(
        self,
        request: dict[str, Any],
        delegation_chain: list[dict[str, Any]],
        *,
        model_evidence: list[dict[str, Any]] | None = None,
    ) -> Authorization:
        """Authenticate and decide ``request``; the caller must then :meth:`complete` it."""
        model = self._authenticate(request, delegation_chain, self.clock())
        try:
            evidence = [parse(ModelEvidence, item) for item in model_evidence or []]
        except MalformedDocumentError as exc:
            raise RequestRejected(str(exc)) from exc
        request_digest = digest(request)
        with self._lock:
            if self.ledger.contains_request(request_digest) or request_digest in self._in_flight:
                raise RequestRejected("request was already processed (replay)")
            self._in_flight.add(request_digest)
        return Authorization(
            request=request,
            model=model,
            request_digest=request_digest,
            delegation_chain=delegation_chain,
            decision=self.policy.evaluate(model.action, model.resource),
            model_evidence=evidence,
        )

    def attach_approval(self, auth: Authorization, approval: dict[str, Any]) -> Authorization:
        """Return ``auth`` with a checked approval (or rejection) attached."""
        if not auth.awaiting_approval:
            raise RequestRejected("this request is not awaiting approval")
        problems, approval_model = approval_problems(
            approval, request_digest=auth.request_digest, decision=auth.decision
        )
        if problems or approval_model is None:
            raise RequestRejected("approval rejected: " + "; ".join(problems))
        return replace(auth, approval=approval)

    def release(self, auth: Authorization) -> None:
        """Drop an authorization without a receipt, so the same request may be retried."""
        with self._lock:
            self._in_flight.discard(auth.request_digest)

    def complete(
        self,
        auth: Authorization,
        *,
        result: JsonValue | None = None,
        error_type: str | None = None,
    ) -> dict[str, Any]:
        """Issue and record the receipt for ``auth``.

        For an allowed request, pass the tool's ``result``, or ``error_type`` if it failed.
        A request that isn't allowed is recorded as not executed, whatever is passed.
        """
        if not auth.allowed:
            outcome = Outcome(status="not_executed", result_digest=None, error_type=None)
        elif error_type is not None:
            outcome = Outcome(status="failed", result_digest=None, error_type=error_type[:256])
        else:
            try:
                outcome = Outcome(status="succeeded", result_digest=digest(result), error_type=None)
            except CanonicalizationError:
                outcome = Outcome(status="failed", result_digest=None, error_type="InvalidResult")
        with self._lock:
            receipt = to_document(
                Receipt(
                    type="agentproof.receipt/v0.1",
                    id="rcp_" + secrets.token_hex(12),
                    issuer=self.key.key_id,
                    issued_at=format_ts(self.clock()),
                    request=auth.model,
                    request_digest=auth.request_digest,
                    delegation_chain=[parse(Delegation, link) for link in auth.delegation_chain],
                    decision=auth.decision,
                    approval=parse(Approval, auth.approval) if auth.approval is not None else None,
                    outcome=outcome,
                    model_evidence=auth.model_evidence,
                    prev=self.ledger.head,
                    signature=None,
                )
            )
            receipt = sign(receipt, self.key)
            self.ledger.append(receipt)
            self._in_flight.discard(auth.request_digest)
        return receipt

    def execute(
        self,
        request: dict[str, Any],
        delegation_chain: list[dict[str, Any]],
        tool: Tool,
        *,
        approver: Approver | None = None,
        model_evidence: list[dict[str, Any]] | None = None,
    ) -> ExecutionResult:
        """Authorize, collect an approval if needed, run ``tool`` if allowed, and receipt it."""
        auth = self.authorize(request, delegation_chain, model_evidence=model_evidence)
        if auth.awaiting_approval and approver is not None:
            try:
                approval = approver(request, auth.decision)
                if approval is not None:
                    auth = self.attach_approval(auth, approval)
            except BaseException:
                self.release(auth)
                raise

        if not auth.allowed:
            return ExecutionResult(receipt=self.complete(auth), result=None)
        try:
            result = tool(auth.model.arguments)
            digest(result)
        except CanonicalizationError as exc:
            receipt = self.complete(auth, error_type="InvalidResult")
            return ExecutionResult(receipt=receipt, result=None, error=exc)
        except Exception as exc:  # the tool's failure is recorded, not hidden
            receipt = self.complete(auth, error_type=type(exc).__name__)
            return ExecutionResult(receipt=receipt, result=None, error=exc)
        return ExecutionResult(receipt=self.complete(auth, result=result), result=result)
