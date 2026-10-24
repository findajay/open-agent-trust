# Security policy

OpenAgentTrust is security software. Reports are welcome, including reports about the
protocol design.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report privately through
GitHub's *Report a vulnerability* (Security → Advisories) on this repository. Include
affected versions, a description, reproduction steps and impact. We aim to acknowledge
reports within 5 working days and to agree a disclosure timeline with you.

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.

## Scope

In scope: the AgentProof specification (`protocol/`), the reference implementation
(`src/openagenttrust`) and the CLI. Especially interesting: anything that makes a
verifier accept a receipt it should reject, parser differentials, delegation scope
escalation, and replay. Out of scope: vulnerabilities in the agent frameworks, models or
tools that OpenAgentTrust guards (report those upstream).

## Security design

The threat model and known limitations are in [docs/threat-model.md](docs/threat-model.md).
v0.1 has **not** had an independent security review. Dependencies are scanned with
`pip-audit` (`make audit`, and the nightly `security` workflow).
