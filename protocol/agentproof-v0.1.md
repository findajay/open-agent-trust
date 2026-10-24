# AgentProof v0.1

**Status:** draft. Breaking changes are expected before v1.0. Feedback is welcome as GitHub issues.

AgentProof is a portable format for proving that an AI agent's action was authorized.
A **receipt** ties together:

- who acted (the agent's key),
- who allowed it to act (a delegation chain back to a trust anchor),
- what it asked to do (a signed request),
- which policy decided, and what it decided,
- who approved it, when the policy required approval,
- what happened (the outcome), and optionally which model's output it acted on.

Anyone holding the trusted key ids, and optionally the policy, can verify a receipt
offline. They don't need the agent framework, the gateway or any network service.

The key words MUST, MUST NOT, SHOULD and MAY are used as described in RFC 2119.

## 1. Roles

| Role | Holds a key | Does |
|---|---|---|
| Trust anchor | yes | Issues root delegations (usually an organization). |
| Delegator | yes | Any subject of a delegation with `may_delegate: true`; issues narrower delegations. |
| Agent | yes | Signs action requests. |
| Approver | yes | Signs approvals for requests that the policy holds for approval. |
| Gateway | yes | Enforces policy, runs the tool if allowed, and signs the receipt. |
| Verifier | no | Checks receipts against the key ids it trusts. |

Trust is configuration. A verifier decides which key ids are trust anchors and gateways.
A key id says nothing about whether it is trustworthy.

## 2. Encoding

### 2.1 Canonical JSON

Signatures and digests are computed over the **canonical form** of a JSON value. That
form is RFC 8785 (JCS), restricted so that implementations need no float formatter:

1. Object member names MUST be ASCII.
2. Numbers MUST be integers in the range ±(2^53 − 1). Floating-point values MUST be rejected.
3. Strings MUST be valid Unicode (no lone surrogates).

Within this subset, the output is byte-identical to RFC 8785: members are sorted, there is
no insignificant whitespace, and the encoding is UTF-8. An application that needs
fractional values encodes them as strings or as scaled integers.

### 2.2 Digests

`digest(v)` = `"sha256:"` followed by the lowercase hex SHA-256 of the canonical form of `v`.

### 2.3 Timestamps

UTC, whole seconds, `YYYY-MM-DDTHH:MM:SSZ`.

### 2.4 Key ids

`"ed25519:"` followed by the unpadded base64url encoding of the 32-byte Ed25519 public
key. A key id is self-certifying: a signature can be verified from the id alone.

### 2.5 Signatures

Every signed document has a `type` member and a `signature` member:

```json
"signature": { "alg": "Ed25519", "value": "<base64url, 64 bytes, unpadded>" }
```

The signing input is the ASCII bytes `agentproof/v0.1`, then one `0x00` byte, then the
canonical form of the document with the `signature` member removed. The signing input
includes `type`, so a signature over one document type can't be passed off as another.

### 2.6 Member presence

Every member listed for a document type MUST be present. An optional value is `null`, not
an omitted member. Unknown members MUST be rejected. A conforming parser therefore
reproduces exactly the bytes that were signed.

### 2.7 Name patterns

Delegation scopes and policies match action and resource names with **patterns**. A
pattern is either an exact name, or a prefix followed by one trailing `*` that matches any
name starting with that prefix. `*` alone matches everything. Names themselves MUST NOT
contain `*` or whitespace.

Pattern `P` **covers** pattern `C` when every name that `C` matches is also matched by `P`:

- If `P` is exact, then `C == P`.
- If `P` is `prefix*`, then `C` without its trailing `*` (if any) starts with `prefix`.

## 3. Documents

Test vectors: [`test-vectors/v0.1`](test-vectors/v0.1). JSON Schemas: [`schemas/v0.1`](schemas/v0.1).

### 3.1 Delegation (`agentproof.delegation/v0.1`)

Signed by `issuer`.

| Member | Type | Meaning |
|---|---|---|
| `type` | string | `agentproof.delegation/v0.1` |
| `id` | string | Unique identifier |
| `issuer` | key id | Who grants authority |
| `subject` | key id | Who receives it |
| `subject_name` | string \| null | Human-readable label (not trusted) |
| `scope.actions` | pattern[] | Actions the subject may request |
| `scope.resources` | pattern[] | Resources it may act on |
| `may_delegate` | bool | Whether the subject may issue narrower delegations |
| `not_before`, `expires_at` | timestamp | Validity window (inclusive) |
| `parent` | digest \| null | Digest of the delegation this one narrows; `null` for a root |
| `signature` | signature | |

### 3.2 Action request (`agentproof.request/v0.1`)

Signed by `agent`.

| Member | Type | Meaning |
|---|---|---|
| `type`, `id` | string | |
| `agent` | key id | The requesting agent |
| `action` | name | For example `pump.restart` |
| `resource` | name | For example `plant-7/pump/P-3` |
| `arguments` | object | Tool arguments (canonical JSON subset) |
| `requested_at` | timestamp | |
| `nonce` | string | At least 16 characters of randomness |
| `signature` | signature | |

### 3.3 Approval (`agentproof.approval/v0.1`)

Signed by `approver`.

| Member | Type | Meaning |
|---|---|---|
| `type`, `id` | string | |
| `approver` | key id | |
| `request_digest` | digest | Digest of the exact request being approved |
| `decision` | `approved` \| `rejected` | |
| `decided_at` | timestamp | |
| `reason` | string \| null | |
| `signature` | signature | |

### 3.4 Receipt (`agentproof.receipt/v0.1`)

Signed by `issuer` (the gateway).

| Member | Type | Meaning |
|---|---|---|
| `type`, `id` | string | |
| `issuer` | key id | The gateway |
| `issued_at` | timestamp | |
| `request` | request | The agent's signed request, verbatim |
| `request_digest` | digest | `digest(request)` |
| `delegation_chain` | delegation[] | Root first, ending at the agent (1–16 links) |
| `decision` | object | `effect` (`allow` \| `deny` \| `require_approval`), `policy_id`, `policy_digest`, `rule_id` (string \| null), `approvers` (key id[]), `reason` |
| `approval` | approval \| null | Present when the policy required approval and one was given |
| `outcome` | object | `status` (`succeeded` \| `failed` \| `not_executed`), `result_digest` (digest of the tool result, only when `succeeded`), `error_type` (only when `failed`) |
| `model_evidence` | object[] | See 3.5 |
| `prev` | digest \| null | Digest of the previous receipt from this gateway's ledger |
| `signature` | signature | |

### 3.5 Model evidence

Records which model produced the output that an action was based on: `source`,
`assurance`, `request_id`, `provider_id`, `model`, `route_policy`, `output_digest`.
`assurance` is `gateway_asserted` when only the gateway's receipt signature backs the
record. It is `provider_signed` (reserved) when the model gateway itself signs it.

## 4. Verification

### 4.1 Delegation chain

Given a chain `L[0..n]`, a set of trust anchors, the requesting agent `A` and time `t`
(the request's `requested_at`), the chain is valid when all of these hold:

1. Every `L[i]` parses (section 2.6) and its signature verifies against `L[i].issuer`.
2. `L[i].not_before ≤ t ≤ L[i].expires_at` for every `i`.
3. `L[0].issuer` is a trust anchor and `L[0].parent` is `null`.
4. For `i > 0`: `L[i].parent == digest(L[i-1])`, `L[i].issuer == L[i-1].subject`,
   `L[i-1].may_delegate` is true, and every pattern in `L[i].scope` is covered by some
   pattern in `L[i-1].scope` (actions and resources separately).
5. `L[n].subject == A`.
6. Every link's scope permits the request's action and resource.

### 4.2 Receipt

A receipt verifies when all of these checks pass:

| Check | Rule |
|---|---|
| structure | The receipt parses (section 2.6). |
| gateway-trusted | `issuer` is a trusted gateway. |
| gateway-signature | The receipt signature verifies against `issuer`. |
| request-digest | `request_digest == digest(request)`. |
| agent-signature | The request signature verifies against `request.agent`. |
| timing | `issued_at` is not earlier than `requested_at` minus the allowed clock skew. |
| delegation-chain, delegation-scope | Section 4.1. |
| policy-decision | *If the verifier has the policy:* `decision.policy_digest` equals the policy's digest, and evaluating the policy for (action, resource) reproduces `decision` exactly. |
| approval | *If an approval is present:* `decision.effect` is `require_approval`, the approval's signature verifies, `approver ∈ decision.approvers`, and `request_digest` matches. |
| enforcement | If `outcome.status ≠ not_executed`: `decision.effect ≠ deny`, and if `decision.effect` is `require_approval`, a valid approval with `decision: approved` is present. |

The enforcement check means that a receipt cannot claim an execution its decision forbade,
even when the gateway itself signed it.

### 4.3 Ledger

A gateway appends receipts to a ledger. Receipt `k` has `prev == digest(receipt k-1)`, and
receipt 0 has `prev == null`. A ledger verifies when every receipt verifies, the chain is
unbroken, and no `request_digest` repeats. Removing, reordering or editing any receipt
breaks the chain from that point on.

## 5. Policy

The protocol fixes only the policy **decision** and the **policy digest**. Implementations
MAY use any deterministic policy language. The reference implementation's YAML format:

```yaml
id: plant-7-maintenance@1
default: deny                    # allow | deny, used when no rule matches
rules:
  - id: read-sensors
    effect: allow                # allow | deny | require_approval
    actions: [sensor.read]       # patterns
    resources: ["*"]             # patterns, default ["*"]
  - id: restart-needs-approval
    effect: require_approval
    actions: [pump.restart]
    approvers: ["ed25519:…"]     # required for require_approval
    description: Restarting a pump needs a shift supervisor's approval
```

When rules conflict, `deny` wins over `require_approval`, which wins over `allow`. Among
rules of equal strength, the first in the document wins. The policy digest is
`digest(normalized policy)`, where every member, including defaults, is present. Comments
and formatting therefore don't change the digest, but any change in meaning does.

## 6. Security considerations

- **Gateway compromise.** A compromised gateway key can sign false receipts. It cannot
  forge agent requests, delegations or approvals. Verifiers that hold the policy also
  detect false decisions. Rotate gateway keys, and anchor ledger heads externally
  (roadmap: transparency log).
- **Replay.** Gateways MUST reject a request whose digest is already in their ledger, and
  SHOULD reject requests outside a short freshness window (the reference uses 5 minutes).
- **Revocation.** v0.1 has none. Short delegation lifetimes are the mitigation.
  Revocation lists are on the roadmap.
- **Privacy.** Receipts contain request arguments verbatim. Don't put secrets in them.
  Tool results appear only as digests.
- **Model evidence** marked `gateway_asserted` is only as trustworthy as the gateway.

## 7. Versioning

The version appears in every `type` and in the signing domain. A verifier MUST reject
types it doesn't implement.
