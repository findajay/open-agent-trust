"""Independent verification of receipts and receipt ledgers.

A verifier needs only the receipt, the key ids it trusts (anchors and gateways) and,
optionally, the policy. It does not need the agent framework, the gateway or network
access. Each check is reported separately so a failure says exactly what is wrong.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from .canonical import digest
from .delegation import chain_problems, scope_permits
from .models import (
    Approval,
    MalformedDocumentError,
    PolicyDecision,
    Receipt,
    parse,
    to_document,
)
from .policy import Policy
from .signing import verify
from .timeutil import parse_ts

Status = Literal["pass", "fail", "skip"]


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [check for check in self.checks if check.status == "fail"]

    def add(self, name: str, problems: list[str], passed: str) -> None:
        if problems:
            self.checks.append(Check(name, "fail", "; ".join(problems)))
        else:
            self.checks.append(Check(name, "pass", passed))

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks
            ],
        }


def approval_problems(
    approval: Any, *, request_digest: str, decision: PolicyDecision
) -> tuple[list[str], Approval | None]:
    """Problems with ``approval`` as authorisation for one request under ``decision``."""
    try:
        model = parse(Approval, approval)
    except MalformedDocumentError as exc:
        return [str(exc)], None
    problems = []
    if not verify(approval, model.approver):
        problems.append("approval signature is not valid for its approver")
    if model.approver not in decision.approvers:
        problems.append("approver is not authorised by the matched policy rule")
    if model.request_digest != request_digest:
        problems.append("approval is for a different request")
    return problems, model


def verify_receipt(
    receipt: Any,
    *,
    trust_anchors: Collection[str],
    gateways: Collection[str],
    policy: Policy | None = None,
    max_clock_skew: timedelta = timedelta(minutes=5),
) -> Report:
    report = Report()
    try:
        model = parse(Receipt, receipt)
    except MalformedDocumentError as exc:
        report.checks.append(Check("structure", "fail", str(exc)))
        return report
    report.checks.append(Check("structure", "pass", "valid agentproof.receipt/v0.1"))
    request_doc = receipt["request"]
    request = model.request
    decision = model.decision

    report.add(
        "gateway-trusted",
        [] if model.issuer in gateways else ["issuer is not a trusted gateway"],
        "issued by a trusted gateway",
    )
    report.add(
        "gateway-signature",
        [] if verify(receipt, model.issuer) else ["receipt signature is not valid"],
        "receipt signature valid",
    )
    report.add(
        "request-digest",
        [] if digest(request_doc) == model.request_digest else ["request_digest mismatch"],
        "request_digest matches the embedded request",
    )
    report.add(
        "agent-signature",
        [] if verify(request_doc, request.agent) else ["request signature is not valid"],
        "request signed by the agent",
    )

    requested_at = parse_ts(request.requested_at)
    timing = []
    if parse_ts(model.issued_at) < requested_at - max_clock_skew:
        timing.append("receipt issued before the request was made")
    report.add("timing", timing, "receipt issued after the request")

    chain_docs = receipt["delegation_chain"]
    report.add(
        "delegation-chain",
        chain_problems(
            chain_docs, trust_anchors=trust_anchors, agent=request.agent, at=requested_at
        ),
        f"{len(chain_docs)}-link chain from a trust anchor to the agent",
    )
    out_of_scope = [
        f"link {index} does not permit {request.action} on {request.resource}"
        for index, link in enumerate(model.delegation_chain)
        if not scope_permits(link.scope, request.action, request.resource)
    ]
    report.add("delegation-scope", out_of_scope, "every link permits the action and resource")

    if policy is None:
        report.checks.append(Check("policy-decision", "skip", "no policy supplied"))
    else:
        expected = to_document(policy.evaluate(request.action, request.resource))
        actual = to_document(decision)
        problems = []
        if decision.policy_digest != policy.digest:
            problems.append("receipt was decided under a different policy (digest mismatch)")
        elif expected != actual:
            problems.append(f"policy yields {expected['effect']}, receipt says {decision.effect}")
        report.add("policy-decision", problems, f"policy reproduces '{decision.effect}'")

    executed = model.outcome.status != "not_executed"
    approval_ok = False
    if model.approval is None:
        report.checks.append(Check("approval", "skip", "no approval attached"))
    elif decision.effect != "require_approval":
        report.checks.append(
            Check("approval", "fail", "approval attached to a non-approval decision")
        )
    else:
        problems, approval = approval_problems(
            receipt["approval"], request_digest=model.request_digest, decision=decision
        )
        approval_ok = not problems and approval is not None and approval.decision == "approved"
        report.add(
            "approval",
            problems,
            f"{approval.decision if approval else ''} by an authorised approver",
        )

    consistency = []
    if executed and decision.effect == "deny":
        consistency.append("a denied request was executed")
    if executed and decision.effect == "require_approval" and not approval_ok:
        consistency.append("executed without a valid approval")
    report.add(
        "enforcement", consistency, f"outcome '{model.outcome.status}' respects the decision"
    )
    return report


def verify_ledger(
    receipts: Iterable[Any],
    *,
    trust_anchors: Collection[str],
    gateways: Collection[str],
    policy: Policy | None = None,
) -> Report:
    """Verify every receipt and the hash chain that links them."""
    report = Report()
    previous: str | None = None
    seen_requests: set[str] = set()
    count = 0
    for index, receipt in enumerate(receipts):
        count += 1
        single = verify_receipt(
            receipt, trust_anchors=trust_anchors, gateways=gateways, policy=policy
        )
        for check in single.failures:
            report.checks.append(Check(f"receipt[{index}].{check.name}", "fail", check.detail))
        prev = receipt.get("prev") if isinstance(receipt, dict) else None
        if prev != previous:
            report.checks.append(
                Check(f"receipt[{index}].chain", "fail", "prev does not match the previous receipt")
            )
        request_digest = receipt.get("request_digest") if isinstance(receipt, dict) else None
        if request_digest in seen_requests:
            report.checks.append(
                Check(f"receipt[{index}].replay", "fail", "request already appears in the ledger")
            )
        seen_requests.add(str(request_digest))
        previous = digest(receipt)
    if report.ok:
        report.checks.append(Check("ledger", "pass", f"{count} receipts, chain intact"))
    return report
