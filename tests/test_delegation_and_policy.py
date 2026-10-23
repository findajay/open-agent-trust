from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from openagenttrust import DelegationError, Policy, PolicyError, Scope, SigningKey, issue_delegation
from openagenttrust.delegation import chain_problems, pattern_covers
from openagenttrust.signing import sign

from .conftest import NOW, World


@pytest.mark.parametrize(
    ("parent", "child", "covered"),
    [
        ("*", "anything.*", True),
        ("pump.*", "pump.restart", True),
        ("pump.*", "pump.r*", True),
        ("pump.*", "pumpkin", False),
        ("pump.restart", "pump.restart", True),
        ("pump.restart", "pump.*", False),
        ("pump.r*", "pump.*", False),
    ],
)
def test_pattern_attenuation(parent: str, child: str, covered: bool) -> None:
    assert pattern_covers(parent, child) is covered


def test_valid_chain_has_no_problems(world: World) -> None:
    assert (
        chain_problems(
            world.chain, trust_anchors=[world.org.key_id], agent=world.agent.key_id, at=NOW
        )
        == []
    )


def test_chain_problems_are_specific(world: World) -> None:
    def problems(chain: list[dict[str, object]], at=NOW, anchors=None, agent=None) -> str:
        return "; ".join(
            chain_problems(
                chain,
                trust_anchors=anchors or [world.org.key_id],
                agent=agent or world.agent.key_id,
                at=at,
            )
        )

    assert "not a trust anchor" in problems(world.chain, anchors=[world.agent.key_id])
    assert "not valid at" in problems(world.chain, at=NOW + timedelta(hours=2))
    assert "requesting agent" in problems(world.chain, agent=world.planner.key_id)
    assert "parent digest" in problems([world.chain[0], world.chain[0]])
    assert "signature" in problems([{**world.chain[0], "may_delegate": False}, world.chain[1]])
    assert "empty" in problems([])


def test_widening_the_scope_is_refused(world: World) -> None:
    with pytest.raises(DelegationError, match="exceeds"):
        issue_delegation(
            world.planner,
            world.agent.key_id,
            Scope(actions=["*"], resources=["plant-7/*"]),
            expires_in=timedelta(hours=1),
            parent=world.chain[0],
            now=NOW,
        )


def test_redelegation_requires_may_delegate(world: World) -> None:
    with pytest.raises(DelegationError, match="re-delegation"):
        issue_delegation(
            world.agent,
            SigningKey.generate().key_id,
            Scope(actions=["sensor.read"], resources=["plant-7/*"]),
            expires_in=timedelta(hours=1),
            parent=world.chain[1],
            now=NOW,
        )


def test_forged_widened_link_is_caught_by_the_verifier(world: World) -> None:
    """A planner that signs a wider link than it holds is caught, even with valid signatures."""
    leaf = sign({**world.chain[1], "scope": {"actions": ["*"], "resources": ["*"]}}, world.planner)
    problems = chain_problems(
        [world.chain[0], leaf], trust_anchors=[world.org.key_id], agent=world.agent.key_id, at=NOW
    )
    assert problems == ["link 1: scope exceeds link 0"]


def test_child_expiry_is_capped_at_the_parent(world: World) -> None:
    child = issue_delegation(
        world.planner,
        world.agent.key_id,
        Scope(actions=["sensor.read"], resources=["plant-7/*"]),
        expires_in=timedelta(days=30),
        parent=world.chain[0],
        now=NOW,
    )
    assert child["expires_at"] == world.chain[0]["expires_at"]


def test_policy_precedence_deny_beats_approval_beats_allow(world: World) -> None:
    policy = Policy.from_mapping(
        {
            "id": "p",
            "default": "allow",
            "rules": [
                {"id": "a", "effect": "allow", "actions": ["x.*"]},
                {
                    "id": "b",
                    "effect": "require_approval",
                    "actions": ["x.y"],
                    "approvers": [world.approver.key_id],
                },
                {"id": "c", "effect": "deny", "actions": ["x.y"], "resources": ["secret/*"]},
            ],
        }
    )
    assert policy.evaluate("x.z", "r").rule_id == "a"
    assert policy.evaluate("x.y", "r").effect == "require_approval"
    assert policy.evaluate("x.y", "secret/1").effect == "deny"
    unmatched = policy.evaluate("other", "r")
    assert (unmatched.effect, unmatched.rule_id) == ("allow", None)


def test_policy_digest_ignores_formatting_but_not_meaning(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        "id: p\nrules:\n  - {id: r, effect: allow, actions: [a]}\n", encoding="utf-8"
    )
    (tmp_path / "b.yaml").write_text(
        "# comment\nid: p\ndefault: deny\nrules:\n- id: r\n  effect: allow\n  actions:\n  - a\n"
        "  resources: ['*']\n",
        encoding="utf-8",
    )
    a, b = Policy.load(tmp_path / "a.yaml"), Policy.load(tmp_path / "b.yaml")
    assert a.digest == b.digest
    changed = Policy.from_mapping(
        {"id": "p", "rules": [{"id": "r", "effect": "deny", "actions": ["a"]}]}
    )
    assert changed.digest != a.digest


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (
            {"id": "p", "rules": [{"id": "r", "effect": "require_approval", "actions": ["a"]}]},
            "approver",
        ),
        ({"id": "p", "rules": [{"id": "r", "effect": "allow", "actions": ["a"]}] * 2}, "unique"),
        ({"id": "p", "rules": [], "extra": 1}, "extra"),
        ({"id": "p", "rules": [{"id": "r", "effect": "allow", "actions": ["a*b"]}]}, "pattern"),
    ],
)
def test_invalid_policies(document: dict[str, object], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        Policy.from_mapping(document)
