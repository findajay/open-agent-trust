from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from openagenttrust import Gateway, Ledger, Policy, Scope, SigningKey, issue_delegation

NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)


@dataclass
class World:
    org: SigningKey
    planner: SigningKey
    agent: SigningKey
    approver: SigningKey
    gateway_key: SigningKey
    chain: list[dict[str, Any]]
    policy: Policy
    gateway: Gateway

    @property
    def trust(self) -> dict[str, list[str]]:
        return {"trust_anchors": [self.org.key_id], "gateways": [self.gateway_key.key_id]}


def make_policy(approver: SigningKey) -> Policy:
    return Policy.from_mapping(
        {
            "id": "test-policy@1",
            "rules": [
                {"id": "read", "effect": "allow", "actions": ["sensor.read"]},
                {
                    "id": "restart",
                    "effect": "require_approval",
                    "actions": ["pump.restart"],
                    "approvers": [approver.key_id],
                },
                {"id": "logs", "effect": "deny", "actions": ["logs.*"]},
            ],
        }
    )


@pytest.fixture
def world() -> World:
    org, planner, agent, approver, gateway_key = (SigningKey.generate() for _ in range(5))
    root = issue_delegation(
        org,
        planner.key_id,
        Scope(actions=["sensor.*", "pump.*", "logs.*"], resources=["plant-7/*"]),
        expires_in=timedelta(hours=8),
        may_delegate=True,
        now=NOW - timedelta(minutes=10),
    )
    leaf = issue_delegation(
        planner,
        agent.key_id,
        Scope(actions=["sensor.read", "pump.restart", "logs.delete"], resources=["plant-7/*"]),
        expires_in=timedelta(hours=1),
        parent=root,
        now=NOW - timedelta(minutes=5),
    )
    policy = make_policy(approver)
    gateway = Gateway(
        gateway_key, policy, trust_anchors=[org.key_id], ledger=Ledger(), clock=lambda: NOW
    )
    return World(org, planner, agent, approver, gateway_key, [root, leaf], policy, gateway)
