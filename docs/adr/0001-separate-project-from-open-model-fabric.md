# ADR 0001: A separate project from Open Model Fabric

- Status: accepted
- Date: 2026-10-23

## Context

[Open Model Fabric](https://github.com/findajay/Open-model-fabric) (OMF) is an inference
gateway: routing, model registry, capability evidence and benchmarks. Agent trust
(identity, delegation, policy over actions, verifiable receipts) could be built into it,
or built as its own project.

## Decision

Build OpenAgentTrust as its own repository and package, and integrate with OMF through
an optional adapter.

## Rationale

- **Different layer.** OMF sees model calls. It passes tool calls through to the client
  and does not execute them, so the action enforcement point is above OMF.
- **Different users.** Teams that run agents on hosted models need agent trust without
  running an inference gateway. Teams that self-host models need OMF without agent
  governance.
- **Protocol adoption.** AgentProof should be implementable without either platform.
  Bundling it with a gateway would make it look like one product's log format.
- **Scope.** OMF keeps a one-sentence pitch.

## Consequences

- An `integrations/openmodelfabric` adapter turns OMF responses into model evidence.
- Shared concerns (OIDC, API keys, audit) are implemented twice for now. Extract a shared
  library only when both projects actually need the same code.
- Signed model evidence (`provider_signed`) requires a later change in OMF.
