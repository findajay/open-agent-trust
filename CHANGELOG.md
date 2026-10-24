# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break).

## [Unreleased]

## [0.1.0]

### Added

- AgentProof v0.1 draft specification, JSON Schemas and signature test vectors.
- Python reference implementation: Ed25519 identities, delegation chains with
  attenuation, deterministic YAML policies, a gateway with approvals and replay
  protection, a hash-chained receipt ledger and an independent verifier.
- `oat` CLI: `keygen`, `key-id`, `delegate`, `policy check`, `proof verify`,
  `ledger verify`, `schema` and `demo`.
- Open Model Fabric integration that records model evidence in receipts.
