from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from openagenttrust import Ledger
from openagenttrust.cli import main
from openagenttrust.demo import run_demo
from openagenttrust.integrations.openmodelfabric import (
    OpenModelFabricClient,
    OpenModelFabricError,
)
from openagenttrust.schemas import render, schema_files

ROOT = Path(__file__).parents[1]

OMF_RESPONSE = {
    "request_id": "req-123",
    "provider_id": "mock",
    "model": "mock-chat",
    "model_id": None,
    "message": {"role": "assistant", "content": "Check the inlet valve first."},
    "finish_reason": "stop",
    "usage": None,
    "timings": {"total_ms": 3},
    "route": {"policy": "default", "provider_id": "mock", "model": "mock-chat", "attempts": []},
    "conversation_id": None,
}


def omf_transport(status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer secret-token"
        return httpx.Response(status, json=OMF_RESPONSE if status == 200 else {"detail": "x"})

    return httpx.MockTransport(handler)


def test_omf_client_builds_evidence() -> None:
    client = OpenModelFabricClient("http://omf", "secret-token", transport=omf_transport())
    call = client.chat([{"role": "user", "content": "hi"}])
    assert call.text == "Check the inlet valve first."
    assert call.evidence["provider_id"] == "mock"
    assert call.evidence["assurance"] == "gateway_asserted"
    assert call.evidence["route_policy"] == "default"


def test_omf_errors_are_reported() -> None:
    client = OpenModelFabricClient("http://omf", "secret-token", transport=omf_transport(503))
    with pytest.raises(OpenModelFabricError, match="503"):
        client.chat([{"role": "user", "content": "hi"}])


def test_demo_end_to_end_and_cli_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "demo"
    assert run_demo(out, echo=lambda _: None)
    receipts = sorted((out / "receipts").glob("0*.json"))
    assert [p.name for p in receipts] == [
        "01-sensor.read.json",
        "02-pump.restart.json",
        "03-logs.delete.json",
    ]
    assert len(Ledger(out / "ledger.jsonl")) == 3

    trust = ["--trust", str(out / "trust.json"), "--policy", str(out / "policy.yaml")]
    assert main(["proof", "verify", str(receipts[1]), *trust]) == 0
    assert main(["ledger", "verify", str(out / "ledger.jsonl"), *trust]) == 0
    capsys.readouterr()
    assert main(["proof", "verify", str(out / "receipts" / "tampered.json"), *trust, "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False

    # Refuses to reuse a non-empty directory instead of overwriting anything in it.
    assert main(["demo", "--out", str(out)]) == 2


def test_demo_with_open_model_fabric_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_client = OpenModelFabricClient.__init__

    def patched(
        self: OpenModelFabricClient, base_url: str, token: str | None = None, **kw: object
    ) -> None:
        real_client(self, base_url, "secret-token", transport=omf_transport())

    monkeypatch.setattr(OpenModelFabricClient, "__init__", patched)
    assert run_demo(tmp_path / "d", omf_url="http://omf", echo=lambda _: None)
    receipt = json.loads((tmp_path / "d" / "receipts" / "01-sensor.read.json").read_text("utf-8"))
    assert receipt["model_evidence"][0]["source"] == "openmodelfabric"


def test_keygen_delegate_and_policy_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    org, agent = tmp_path / "org.json", tmp_path / "agent.json"
    assert main(["keygen", str(org), "--name", "org"]) == 0
    assert main(["keygen", str(agent)]) == 0
    assert main(["keygen", str(agent)]) == 2  # no silent overwrite
    capsys.readouterr()
    assert (
        main(
            [
                "delegate",
                "--issuer-key",
                str(org),
                "--subject",
                str(agent),
                "--action",
                "sensor.*",
                "--resource",
                "plant-7/*",
                "--expires-in",
                "2h",
                "--out",
                str(tmp_path / "d.json"),
            ]
        )
        == 0
    )
    delegation = json.loads((tmp_path / "d.json").read_text("utf-8"))
    assert delegation["scope"] == {"actions": ["sensor.*"], "resources": ["plant-7/*"]}
    assert main(["proof", "verify", str(tmp_path / "d.json")]) == 2  # no trust configured


def test_quickstart_example_runs(capsys: pytest.CaptureFixture[str]) -> None:
    namespace: dict[str, object] = {"__name__": "quickstart"}
    exec((ROOT / "examples" / "quickstart.py").read_text("utf-8"), namespace)
    namespace["main"]()  # type: ignore[operator]
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[1:] for line in lines] == [
        ["allow", "succeeded", "verified=True"],
        ["require_approval", "succeeded", "verified=True"],
        ["deny", "not_executed", "verified=True"],
    ]


def test_checked_in_schemas_are_current() -> None:
    directory = ROOT / "protocol" / "schemas" / "v0.1"
    for name, schema in schema_files().items():
        path = directory / name
        assert path.exists(), f"run `make schemas` ({name} missing)"
        assert path.read_text(encoding="utf-8") == render(schema), f"run `make schemas` ({name})"
