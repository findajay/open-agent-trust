# Architecture

## Layers

```text
openagenttrust/
  canonical.py     canonical JSON + digests              (no dependencies)
  keys.py          Ed25519 keys, key ids, JWK files      (cryptography)
  signing.py       domain-separated document signatures
  models.py        AgentProof v0.1 document types        (pydantic)
  timeutil.py      timestamp and duration handling
  delegation.py    issue + validate delegation chains
  policy.py        deterministic policy evaluation       (pyyaml)
  requests.py      agent requests and approvals
  ledger.py        append-only hash-chained receipt log
  gateway.py       enforcement point: authenticate → decide → execute → receipt
  verify.py        independent verification of receipts and ledgers
  integrations/    optional adapters (Open Model Fabric)
  cli.py, demo.py  `oat` command line
```

Dependencies only point downward. `verify.py` doesn't import `gateway.py`, so a verifier
can be shipped without any enforcement code.

## Design rules

1. **The verifier is the product.** Every claim the gateway makes must be checkable from
   the receipt plus public configuration. If a feature can't be verified independently,
   it doesn't belong in a receipt.
2. **Authority only narrows.** Delegations attenuate. A link can never grant more than
   its parent, and the verifier re-checks this rather than trusting the issuer.
3. **Deterministic enforcement.** Policy evaluation is pure and needs no network or
   model. Risk-adaptive behavior comes from rules (`require_approval`), not from an LLM
   supervising another LLM.
4. **Exact bytes.** Documents round-trip exactly (all members present, no coercion), so
   there is never a question about what was signed.
5. **Small trusted core.** Three runtime dependencies. Integrations are optional extras.

## Relationship to Open Model Fabric

[Open Model Fabric](https://github.com/findajay/Open-model-fabric) is the model layer: it
routes inference across engines. OpenAgentTrust is the action layer: it decides and
proves what agents may do. They are separate projects with separate release cycles (see
[ADR 0001](adr/0001-separate-project-from-open-model-fabric.md)). The `omf` integration
turns an Open Model Fabric response into `model_evidence` on a receipt.
