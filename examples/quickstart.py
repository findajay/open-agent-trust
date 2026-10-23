"""Smallest useful OpenAgentTrust program: delegate, enforce, verify.

Run with ``uv run python examples/quickstart.py``.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from openagenttrust import (
    Gateway,
    Ledger,
    Policy,
    Scope,
    SigningKey,
    create_approval,
    create_request,
    issue_delegation,
    verify_receipt,
)


def main() -> None:
    org = SigningKey.generate("acme")  # trust anchor
    agent = SigningKey.generate("ops-agent")
    approver = SigningKey.generate("on-call-engineer")
    gateway_key = SigningKey.generate("gateway")

    # The organization lets the agent touch staging services for one hour.
    chain = [
        issue_delegation(
            org,
            agent.key_id,
            Scope(actions=["service.*"], resources=["staging/*"]),
            expires_in=timedelta(hours=1),
        )
    ]

    policy = Policy.from_mapping(
        {
            "id": "staging-ops@1",
            "rules": [
                {"id": "status", "effect": "allow", "actions": ["service.status"]},
                {
                    "id": "deploys",
                    "effect": "require_approval",
                    "actions": ["service.deploy"],
                    "approvers": [approver.key_id],
                },
            ],
        }
    )
    gateway = Gateway(gateway_key, policy, trust_anchors=[org.key_id], ledger=Ledger())

    def on_call(request: dict[str, Any], decision: object) -> dict[str, Any]:
        return create_approval(approver, request, reason="change ticket 4711")

    for action in ("service.status", "service.deploy", "service.delete"):
        request = create_request(agent, action, "staging/checkout", {"version": "1.4.2"})
        result = gateway.execute(request, chain, lambda args: {"ok": True}, approver=on_call)
        report = verify_receipt(
            result.receipt,
            trust_anchors=[org.key_id],
            gateways=[gateway_key.key_id],
            policy=policy,
        )
        print(f"{action:<15} {result.effect:<17} {result.status:<13} verified={report.ok}")


if __name__ == "__main__":
    main()
