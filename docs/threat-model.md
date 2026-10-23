# Threat model (v0.1)

## Assets

- The authority to act on resources (delegations).
- The integrity of the action record (receipts and ledger).
- Private keys: trust anchor, delegators, agents, approvers and gateway.

## Assumptions

- Ed25519 and SHA-256 are secure.
- Verifiers obtain trusted key ids and policies through a channel the attacker doesn't control.
- Each gateway owns its ledger file; there is a single writer.

## Threats and mitigations

| # | Threat | Mitigation in v0.1 | Residual risk / roadmap |
|---|---|---|---|
| T1 | Agent acts outside its authority | Gateway rejects requests not permitted by every delegation link; verifier re-checks. | — |
| T2 | Delegator widens authority when re-delegating | Attenuation is checked at issuance and again by the verifier. | — |
| T3 | Forged or altered request | Agent signature over the canonical request; `request_digest` binds it to the receipt. | — |
| T4 | Replay of a captured request | Gateway rejects duplicate request digests and requests outside a 5-minute window; verifier rejects duplicates in a ledger. | Separate gateways don't share replay state yet. |
| T5 | Approval reused for another request | Approval signs the request digest; approver must be listed by the matched rule. | — |
| T6 | Receipt or ledger edited after the fact | Gateway signature; hash chain over the ledger. | Truncating the tail is undetectable without an external anchor (roadmap: anchor ledger heads). |
| T7 | Gateway claims a decision the policy wouldn't make | Verifier with the policy re-evaluates and compares the policy digest. | Verifiers without the policy see only the gateway's claim. |
| T8 | Gateway executes a denied or unapproved action and records it honestly | `enforcement` check fails. | A compromised gateway can execute *and lie*; receipts prove what was authorized, not that nothing else happened. Pair with tool-side enforcement. |
| T9 | Stolen agent key | Short delegation lifetimes. | No revocation in v0.1 (roadmap). |
| T10 | Stolen gateway key | Verifiers configure which gateways they trust. | Key rotation tooling and transparency logging are on the roadmap. |
| T11 | Parser differentials between implementations | Strict canonical subset, all-members-present rule, unknown members rejected, published test vectors. | More vectors needed (negative cases). |
| T12 | Sensitive data leaks through receipts | Tool results appear only as digests. | Request arguments are stored verbatim; don't put secrets in them. |
| T13 | Model evidence is fabricated | Marked `gateway_asserted`. | Signed evidence from the model gateway is on the roadmap. |

## Out of scope for v0.1

Network transport security between agent and gateway, key storage (keys are JWK files
with owner-only permissions), denial of service, and side channels.
