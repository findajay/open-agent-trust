"""End-to-end demo: a maintenance agent acting on an industrial plant.

Creates an organisation (trust anchor), a planner agent, a maintenance agent it
delegates to, an approver and a gateway; runs four requests through the gateway
(allowed, approved, denied, out of scope); then verifies the ledger and shows that a
tampered receipt fails verification. Everything is written to one directory so the
receipts can be re-verified with ``oat proof verify``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .delegation import issue_delegation
from .gateway import ExecutionResult, Gateway, RequestRejected, Tool
from .keys import SigningKey
from .ledger import Ledger
from .models import PolicyDecision, Scope
from .policy import Policy
from .requests import create_approval, create_request
from .verify import verify_ledger, verify_receipt

Echo = Callable[[str], None]


def _write_json(path: Path, document: Any) -> None:
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _model_step(omf_url: str | None, omf_token: str | None, echo: Echo) -> list[dict[str, Any]]:
    if not omf_url:
        echo("  model: offline (pass --omf-url to attach Open Model Fabric evidence)")
        return []
    from .integrations.openmodelfabric import OpenModelFabricClient

    with OpenModelFabricClient(omf_url, omf_token) as client:
        call = client.chat(
            [
                {
                    "role": "user",
                    "content": "Pump P-3 at plant 7 reports low pressure. "
                    "In one sentence, what should a maintenance agent do first?",
                }
            ]
        )
    evidence = call.evidence
    echo(f"  model: {evidence['provider_id']}/{evidence['model']} via Open Model Fabric")
    echo(f'         "{call.text.strip()[:100]}"')
    return [evidence]


def run_demo(
    out_dir: Path,
    *,
    omf_url: str | None = None,
    omf_token: str | None = None,
    echo: Echo = print,
) -> bool:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(f"{out_dir} is not empty; choose a new directory with --out")
    (out_dir / "keys").mkdir(parents=True)
    (out_dir / "receipts").mkdir()

    echo("1. Identities")
    org = SigningKey.generate("acme-industries")
    planner = SigningKey.generate("planner-agent")
    agent = SigningKey.generate("maintenance-agent")
    approver = SigningKey.generate("shift-supervisor")
    gateway_key = SigningKey.generate("plant-7-gateway")
    for key in (org, planner, agent, approver, gateway_key):
        key.save(out_dir / "keys" / f"{key.name}.json")
        echo(f"   {key.name:<18} {key.key_id[:24]}...")
    trust = {"trust_anchors": [org.key_id], "gateways": [gateway_key.key_id]}
    _write_json(out_dir / "trust.json", trust)

    echo("2. Delegation: acme-industries -> planner-agent -> maintenance-agent")
    root = issue_delegation(
        org,
        planner.key_id,
        Scope(actions=["sensor.*", "pump.*", "logs.*"], resources=["plant-7/*"]),
        expires_in=timedelta(hours=8),
        may_delegate=True,
        subject_name="planner-agent",
    )
    leaf = issue_delegation(
        planner,
        agent.key_id,
        Scope(actions=["sensor.read", "pump.restart", "logs.delete"], resources=["plant-7/*"]),
        expires_in=timedelta(hours=1),
        parent=root,
        subject_name="maintenance-agent",
    )
    chain = [root, leaf]
    _write_json(out_dir / "delegation-chain.json", chain)

    echo("3. Policy: read freely, restart needs a supervisor, never delete logs")
    policy_doc = {
        "id": "plant-7-maintenance@1",
        "default": "deny",
        "rules": [
            {"id": "read-sensors", "effect": "allow", "actions": ["sensor.read"]},
            {
                "id": "restart-needs-approval",
                "effect": "require_approval",
                "actions": ["pump.restart"],
                "approvers": [approver.key_id],
                "description": "Restarting a pump needs a shift supervisor's approval",
            },
            {
                "id": "protect-logs",
                "effect": "deny",
                "actions": ["logs.*"],
                "description": "Audit logs are never deleted by agents",
            },
        ],
    }
    (out_dir / "policy.yaml").write_text(yaml.safe_dump(policy_doc, sort_keys=False), "utf-8")
    policy = Policy.load(out_dir / "policy.yaml")

    gateway = Gateway(
        gateway_key,
        policy,
        trust_anchors=trust["trust_anchors"],
        ledger=Ledger(out_dir / "ledger.jsonl"),
    )

    def supervisor(request: dict[str, Any], decision: PolicyDecision) -> dict[str, Any]:
        return create_approval(approver, request, reason="Pressure confirmed low on site")

    tools: dict[str, Tool] = {
        "sensor.read": lambda args: {"pressure_bar": 1, "status": "low"},
        "pump.restart": lambda args: {"restarted": True},
        "logs.delete": lambda args: {"deleted": True},
    }

    echo("4. Agent actions through the gateway")
    evidence = _model_step(omf_url, omf_token, echo)
    actions = [
        ("sensor.read", "plant-7/pump/P-3"),
        ("pump.restart", "plant-7/pump/P-3"),
        ("logs.delete", "plant-7/logs/2026-10"),
        ("pump.restart", "plant-9/pump/P-1"),
    ]
    results: list[ExecutionResult] = []
    for index, (action, resource) in enumerate(actions, 1):
        request = create_request(agent, action, resource, {"reason": "low pressure alarm"})
        try:
            result = gateway.execute(
                request, chain, tools[action], approver=supervisor, model_evidence=evidence
            )
        except RequestRejected as exc:
            echo(f"   {action:<13} {resource:<22} REJECTED  no receipt ({exc})")
            continue
        results.append(result)
        name = f"{index:02d}-{action}.json"
        _write_json(out_dir / "receipts" / name, result.receipt)
        echo(f"   {action:<13} {resource:<22} {result.effect:<17} {result.status:<13} {name}")

    echo("5. Independent verification")
    report = verify_ledger(
        gateway.ledger,
        trust_anchors=trust["trust_anchors"],
        gateways=trust["gateways"],
        policy=policy,
    )
    for check in report.checks:
        echo(f"   [{check.status}] {check.name}: {check.detail}")

    tampered = json.loads(json.dumps(results[2].receipt))
    tampered["outcome"] = {
        "status": "succeeded",
        "result_digest": tampered["request_digest"],
        "error_type": None,
    }
    _write_json(out_dir / "receipts" / "tampered.json", tampered)
    tamper_report = verify_receipt(
        tampered,
        trust_anchors=trust["trust_anchors"],
        gateways=trust["gateways"],
        policy=policy,
    )
    echo("   tampered copy of the denied receipt (outcome rewritten to 'succeeded'):")
    for check in tamper_report.failures:
        echo(f"   [fail] {check.name}: {check.detail}")

    echo("")
    echo(f"Everything is in {out_dir}. Verify a receipt yourself:")
    echo(
        f"  oat proof verify {out_dir / 'receipts' / '02-pump.restart.json'} "
        f"--trust {out_dir / 'trust.json'} --policy {out_dir / 'policy.yaml'}"
    )
    return report.ok and not tamper_report.ok
