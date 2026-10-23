# Roadmap

Items are ordered within each milestone. Nothing here is a commitment to a date.

## v0.1: protocol and reference implementation (current)

- [x] AgentProof v0.1 draft: delegation, request, approval and receipt documents
- [x] Canonical JSON, Ed25519 signatures, test vectors, JSON Schemas
- [x] Delegation chains with attenuation and expiry
- [x] Deterministic YAML policy with `allow` / `deny` / `require_approval`
- [x] Gateway with replay protection and a hash-chained receipt ledger
- [x] Independent verifier and `oat` CLI
- [x] Open Model Fabric model-invocation evidence

## v0.2: enforce real tool calls

- [ ] MCP gateway: a proxy that enforces policy on MCP `tools/call` and issues receipts
- [ ] Agent SDK helpers for at least one framework (OpenAI Agents SDK or LangGraph)
- [ ] Delegation revocation lists
- [ ] Policy adapters: OPA (Rego) and Cedar
- [ ] TypeScript verifier package, conformance-tested against the vectors

## v0.3: operations

- [ ] Studio: browse ledgers, inspect delegation chains, verify receipts in the browser
- [ ] Persistent ledger backends (PostgreSQL) and external anchoring of ledger heads
- [ ] OpenTelemetry spans linked to receipts
- [ ] Key storage via KMS / HSM

## Later, and subject to demand

- Cross-organization federation: verify delegation chains that span trust domains
- Signed model evidence from Open Model Fabric (`provider_signed`)
- Policy replay: re-evaluate historical ledgers against a candidate policy
- Optional adapters for other agent-security projects, after a license review of each
