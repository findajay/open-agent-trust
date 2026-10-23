# ADR 0002: Python reference implementation first

- Status: accepted
- Date: 2026-10-23

## Context

The initial plan proposed Rust for verification, Go for gateways, React for Studio and
SDKs in Python, TypeScript and .NET. That is five toolchains before the first user.

## Decision

v0.1 ships one Python package that contains the reference implementation of every role
(issuer, agent, approver, gateway, verifier). The protocol is specified independently,
with JSON Schemas and test vectors, so other implementations can follow.

## Rationale

- Most agent frameworks are Python-first, so the gateway and SDK land where users are.
- The same team maintains Open Model Fabric, which uses Python with the same tooling
  (uv, ruff, strict mypy, pytest).
- A small, readable reference implementation is the best way to pin down a draft protocol.
- Ed25519 and SHA-256 come from `cryptography` (OpenSSL), so performance-critical
  primitives are not written in Python.

## Consequences

- A second implementation (TypeScript verifier) is the first real test of the spec, and
  it is planned for v0.2.
- If verification throughput ever matters, a Rust verifier can be added behind the
  same test vectors.
