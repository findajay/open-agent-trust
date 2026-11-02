# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break).

## [Unreleased]

### Added

- `oat serve`: the gateway as an HTTP API. Submit actions, approve or reject pending
  ones (long-polling until decided), report outcomes, browse and verify receipts.
- `oat mcp-proxy`: runs a stdio MCP server behind the gateway; every `tools/call` is
  signed as the agent, decided by policy, approved if required and receipted. Blocked
  calls fail closed with a tool error the model can read.
- `Gateway.authorize()`, `attach_approval()`, `complete()` and `release()`: the two phases
  of `execute()`, for tools that run elsewhere or approvals that arrive later.
- `receipt_reference()` and `Ledger.find()` for `agentproof:sha256:…` references.
- `github:pr:<owner>/<repo>#<number>` reference kind; `oat mcp-proxy --reference` adds
  reference URIs to every signed request, and `GET /v1/receipts?reference=` finds a
  change's receipts.

## [0.1.0]

### Added

- AgentProof v0.1 draft specification, JSON Schemas and signature test vectors.
- Python reference implementation: Ed25519 identities, delegation chains with
  attenuation, deterministic YAML policies, a gateway with approvals and replay
  protection, a hash-chained receipt ledger and an independent verifier.
- `oat` CLI: `keygen`, `key-id`, `delegate`, `policy check`, `proof verify`,
  `ledger verify`, `schema` and `demo`.
- Open Model Fabric integration that records model evidence in receipts.
