# Gateway API and MCP proxy

Two ways to put the gateway in front of real tool calls:

- **`oat serve`** runs the gateway as an HTTP API. Agents submit signed requests, people
  approve or reject the ones that need approval, and anyone with the token can browse and
  verify the receipt ledger. The Studio's approval screen talks to this API.
- **`oat mcp-proxy`** runs an MCP server behind the gateway. Every `tools/call` is signed
  as the agent, decided by the policy, approved if required, and receipted.

Both use only the Python standard library on top of the core, so they add no dependency.

## Phases of one action

`Gateway.execute()` still does everything in one call. When the tool runs somewhere else,
or the approval arrives later, the gateway works in two phases:

1. `authorize(request, chain)` checks the agent's signature, the delegation chain and the
   replay window, evaluates the policy and returns an `Authorization`. The request is
   reserved, so a replay is rejected even before the receipt exists.
2. Optionally `attach_approval(auth, approval)` when the decision is `require_approval`.
3. `complete(auth, result=… | error_type=…)` issues the signed, hash-chained receipt. A
   request that isn't allowed is recorded as not executed, whatever the caller passes.

`release(auth)` drops an authorization without a receipt (only for requests that should be
retryable, such as one carrying an invalid approval).

## `oat serve`

```bash
oat keygen gateway.json
oat keygen approver.json            # a person's key, listed as an approver in the policy
export OAT_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
oat serve --gateway-key gateway.json --policy policy.yaml --trust trust.json \
  --ledger ledger.jsonl --approver-key approver.json --cors-origin http://localhost:5173
```

It listens on `127.0.0.1:8787` by default. Every request needs
`Authorization: Bearer $OAT_API_TOKEN`; without `OAT_API_TOKEN` a random token is generated
and printed on stderr. Put a TLS-terminating proxy in front before exposing it beyond
loopback.

| Method and path | Body / query | Returns |
|---|---|---|
| `GET /v1/info` | | gateway key, trusted gateways, trust anchors, policy id and digest, approver, ledger length and head |
| `POST /v1/actions` | `{request, delegation_chain, model_evidence?}` | the action; `403` if the request can't be attributed or is out of scope |
| `GET /v1/actions/{id}` | `?wait=SECONDS` (max 60) | the action; with `wait`, blocks while approval is pending |
| `POST /v1/actions/{id}/outcome` | `{result}` or `{error_type}` | the completed action with its receipt |
| `GET /v1/actions` | | `{actions}`: actions still held in memory (finished ones for an hour), newest first |
| `GET /v1/approvals` | | actions awaiting approval, oldest first |
| `POST /v1/approvals/{id}` | `{approval}` (signed document) or `{decision: "approved" \| "rejected", reason?}` | the action |
| `GET /v1/receipts` | `?limit=50&offset=0&reference=URI` | `{total, receipts: [{ref, receipt}]}`, newest first; `reference` keeps receipts whose `request.arguments.references` contains that URI |
| `GET /v1/receipts/{ref}` | `agentproof:sha256:…`, `sha256:…` or a receipt id | `{ref, receipt}` |
| `POST /v1/verify` | `{receipt}` | the verification report (all checks) |
| `GET /v1/ledger` | | the ledger as JSON Lines (`application/x-ndjson`), oldest first |
| `GET /v1/ledger/verify` | | the report for the whole ledger |

An action is `{id, status, agent, agent_name, action, resource, references, request,
request_digest, decision, created_at, deadline, receipt_ref, receipt}`. `agent_name` is the
`subject_name` of the last delegation link and `references` the string items of
`request.arguments.references`; both are for display. Its status moves like this:

```text
POST /v1/actions ──► allowed ──── outcome reported ────► completed
              ├────► denied    (receipt issued at once)
              └────► pending_approval ── approved ──► allowed
                                       └ rejected ──► rejected (receipt issued)
deadline passes:  pending_approval ► expired (not executed)
                  allowed          ► expired (failed, error_type OutcomeNotReported)
```

Every action ends in exactly one receipt. `receipt_ref` is the shared reference URI from
[shared references](integration/shared-references.md).

**Who approves.** A `require_approval` rule names approver key ids. A client that holds an
approver key sends a signed `approval` document, and the server only checks it. For a
browser UI, start the server with `--approver-key`: then `{decision, reason}` is signed
with that key, and the bearer token is what authenticates the person. That is weaker
(anyone with the token approves as that key), so give that key its own policy entry and
keep the token as secret as the key.

## `oat mcp-proxy`

```bash
oat mcp-proxy --agent-key agent.json --chain chain.json --server fs --resource-arg path \
  --gateway-url http://127.0.0.1:8787 \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

Configure your MCP client to start this command instead of the server itself. The proxy
passes every message through unchanged, except `tools/call`:

| Request member | Value |
|---|---|
| `action` | `mcp.<server>.<tool>`, e.g. `mcp.fs.write_file` |
| `resource` | the `--resource-arg` argument when it is a valid name (e.g. the `path`), else `mcp:<server>` |
| `arguments` | the tool arguments (they must be in the canonical JSON subset: no floats) |

With `--reference URI` (repeatable), the proxy also adds those reference URIs to
`arguments.references` of every signed request, merged with any the tool call already has.
Use it to tie a session's actions to the change it works on, e.g.
`--reference github:pr:findajay/Open-model-fabric#42`. Only the signed request carries them;
the MCP server receives the tool call exactly as the client sent it.

A delegation such as `actions: ["mcp.fs.read_*"], resources: ["workspace/*"]` then limits
the agent, and policy rules match the same names.

- **Allowed:** the call goes to the server. The answer goes back with
  `_meta["openagenttrust/receipt"]` set to the receipt reference. The receipt's
  `result_digest` covers the MCP `result`; when it holds floats (outside the canonical
  subset) the digest covers its sorted, compact JSON text instead.
- **Needs approval:** the proxy waits (`--approval-wait`, default 10m) while someone
  approves in the Studio or through `POST /v1/approvals/{id}`.
- **Denied, rejected, out of scope or unreachable gateway:** the server is never called.
  The client gets a tool result with `isError: true` and the reason, so the model sees why.
  The proxy fails closed.
- A server error or an `isError` result is receipted as `failed` (`McpError`, `ToolError`).

Without `--gateway-url`, `--gateway-key`, `--policy` and `--trust` run the gateway in the
proxy process. Nobody can approve there, so `require_approval` calls are not executed.

JSON-RPC batches are split and each message handled on its own, so a `tools/call` can't
bypass the gateway inside a batch.

## Limits of this version

- Pending actions live in memory. Restarting `oat serve` loses them (their requests can be
  re-sent; nothing was receipted).
- One process owns a ledger file. Don't point `oat serve` and a local-mode proxy at the
  same file.
- The proxy speaks the stdio transport only; Streamable HTTP is not proxied yet.
