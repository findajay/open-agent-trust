"""Open Model Fabric integration: model-invocation evidence for receipts.

Calls an Open Model Fabric (https://github.com/findajay/Open-model-fabric) gateway and
turns its response into an AgentProof ``ModelEvidence`` record: which provider and
model answered, under which routing policy, and a digest of the output the agent acted
on. Open Model Fabric does not sign its responses yet, so the evidence is
``gateway_asserted``: the OpenAgentTrust gateway vouches for it with its own signature.

Requires the ``omf`` extra (``pip install 'openagenttrust[omf]'``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from ..canonical import digest
from ..models import ModelEvidence, to_document


class OpenModelFabricError(RuntimeError):
    """The Open Model Fabric gateway returned an error or an unexpected response."""


@dataclass(frozen=True)
class ModelCall:
    text: str
    evidence: dict[str, Any]


def evidence_from_response(body: dict[str, Any]) -> dict[str, Any]:
    """Build ``ModelEvidence`` from an Open Model Fabric chat completion response."""
    try:
        text = str(body["message"]["content"] or "")
        route = body.get("route") or {}
        evidence = ModelEvidence(
            source="openmodelfabric",
            assurance="gateway_asserted",
            request_id=str(body["request_id"]),
            provider_id=str(body["provider_id"]),
            model=str(body["model"]),
            route_policy=route.get("policy"),
            output_digest=digest({"content": text}),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OpenModelFabricError(f"unexpected Open Model Fabric response: {exc}") from exc
    return to_document(evidence)


class OpenModelFabricClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        *,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        provider_id: str | None = None,
        model: str | None = None,
    ) -> ModelCall:
        payload: dict[str, Any] = {"messages": messages}
        if provider_id:
            payload["provider_id"] = provider_id
        if model:
            payload["model"] = model
        try:
            response = self._client.post("/api/v1/chat/completions", json=payload)
        except httpx.HTTPError as exc:
            raise OpenModelFabricError(f"Open Model Fabric is unreachable: {exc}") from exc
        if response.status_code != 200:
            raise OpenModelFabricError(
                f"Open Model Fabric returned HTTP {response.status_code}: {response.text[:200]}"
            )
        body = response.json()
        evidence = evidence_from_response(body)
        return ModelCall(text=str(body["message"]["content"] or ""), evidence=evidence)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OpenModelFabricClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
