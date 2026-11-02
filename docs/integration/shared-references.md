# Shared references between tools (draft)

**Status:** draft contract for the Open Engineering Studio integration. It needs no change
to AgentProof v0.1: it only fixes how tools write references in fields they already have.

The Studio connects independent tools: OpenAgentTrust (agent actions and receipts),
Recall (engineering decisions), BallastOS (model calls and token savings) and a repository
analyzer. To link "this decision explains this code, which this agent changed under this
receipt", every tool writes references to the others in the same form.

## Reference URIs

| Kind | Form | Example |
|---|---|---|
| Receipt | `agentproof:` + receipt digest | `agentproof:sha256:46ab4a67…` |
| Memory | `recall:memory:` + memory id | `recall:memory:3f0c9d2e-8b1a-4c5e-9a77-2d4e6f1b0c13` |
| Code | `git+` repository URL, `@` full commit, `#` path, optional `:L<start>-L<end>` | `git+https://github.com/findajay/Open-model-fabric@cea75b0…#python/omf/core/services/routing.py:L40-L72` |
| Model call | `<gateway>:request:` + the gateway's request id | `omf:request:req-123`, `ballast:request:…` |
| Knowledge item | BallastOS's existing form | `ballast://source/knowledge:<id>` |
| Change (pull request) | `github:pr:` + `<owner>/<repo>#<number>` | `github:pr:findajay/Open-model-fabric#42` |

Rules:

- **Receipts are referenced by digest, not id.** The digest is `digest(receipt)` from the
  AgentProof spec (SHA-256 of the canonical JSON). Anyone holding the receipt can check the
  reference; a receipt id alone is not unique across gateways and proves nothing.
- **Code references pin a full commit hash.** Branch names move.
- **Lowercase schemes, no whitespace.** Tools compare references as plain strings.
- A tool that can't resolve a scheme keeps the reference as an opaque string and shows it
  as text.

## Where each tool writes them today

| Tool | Field | How |
|---|---|---|
| OpenAgentTrust | `request.arguments.references` | A list of reference URIs. Arguments are covered by the agent's signature and the request digest, so the references are tamper-evident inside the receipt. Values must stay in the canonical JSON subset (strings are fine). |
| OpenAgentTrust | `model_evidence[].request_id` with `source` | Already defined. The Studio derives `<source>:request:<request_id>`. |
| Recall | `evidence` (decision field) | One reference URI per line, after any free text. A dedicated links table is planned (see below). |
| BallastOS | source references | Keeps `ballast://source/knowledge:<id>`; adds the request id to its ledger entries. |

Example request arguments for an agent edit:

```json
{
  "path": "python/omf/core/services/routing.py",
  "references": [
    "git+https://github.com/findajay/Open-model-fabric@cea75b0…#python/omf/core/services/routing.py",
    "recall:memory:3f0c9d2e-8b1a-4c5e-9a77-2d4e6f1b0c13"
  ]
}
```

To tie every action of an agent session to the change it works on (the Studio's change
dossier, ADR 0001 in open-engineering-studio), start the MCP proxy with
`--reference github:pr:<owner>/<repo>#<number>`. The proxy adds the reference to each signed
request's `arguments.references` (the MCP server still gets the tool call unchanged), and
`GET /v1/receipts?reference=<uri>` on `oat serve` returns that change's receipts.

After the gateway issues the receipt, Recall can record the outcome with an `evidence` line
`agentproof:sha256:<digest of that receipt>`.

## Planned (not part of this draft's obligations)

- **Recall links table** (`idea_links`: memory id, reference URI, relation such as
  `constrains`, `explains`, `changed-by`), which the Studio's memory graph reads.
- **AgentProof v0.2** may promote `references` from `arguments` to a first-class request
  member with a schema, once the Studio has exercised this form.
