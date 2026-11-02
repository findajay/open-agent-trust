"""``oat``: the OpenAgentTrust command line."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .delegation import DelegationError, issue_delegation
from .gateway import Gateway
from .keys import InvalidKeyError, PublicKey, SigningKey
from .ledger import Ledger, LedgerError
from .models import Scope, to_document
from .policy import Policy, PolicyError
from .schemas import write_schemas
from .timeutil import parse_duration
from .verify import Report, verify_ledger, verify_receipt

TOKEN_ENV = "OAT_API_TOKEN"  # noqa: S105 - a variable name


class CliError(Exception):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"{path}: not valid JSON ({exc})") from exc


def _key_id(value: str) -> str:
    """Accept a key id or the path of a key file."""
    if value.startswith("ed25519:"):
        try:
            return PublicKey.from_key_id(value).key_id
        except InvalidKeyError as exc:
            raise CliError(f"invalid key id {value!r}: {exc}") from exc
    path = Path(value)
    if not path.exists():
        raise CliError(f"{value!r} is neither a key id nor an existing key file")
    data = _read_json(path)
    kid = data.get("kid") if isinstance(data, dict) else None
    if not isinstance(kid, str):
        raise CliError(f"{path}: no 'kid' member")
    return _key_id(kid)


def _signing_key(path: str) -> SigningKey:
    try:
        return SigningKey.load(Path(path))
    except FileNotFoundError as exc:
        raise CliError(f"{path}: file not found") from exc
    except (InvalidKeyError, json.JSONDecodeError) as exc:
        raise CliError(f"{path}: not a valid key file ({exc})") from exc


def _trust(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    anchors = [_key_id(v) for v in args.anchor]
    gateways = [_key_id(v) for v in args.gateway]
    if args.trust:
        data = _read_json(Path(args.trust))
        anchors += [_key_id(v) for v in data.get("trust_anchors", [])]
        gateways += [_key_id(v) for v in data.get("gateways", [])]
    if not anchors or not gateways:
        raise CliError("give at least one --anchor and one --gateway (or --trust FILE)")
    return anchors, gateways


def _policy(args: argparse.Namespace) -> Policy | None:
    if not args.policy:
        return None
    try:
        return Policy.load(Path(args.policy))
    except FileNotFoundError as exc:
        raise CliError(f"{args.policy}: file not found") from exc
    except PolicyError as exc:
        raise CliError(f"{args.policy}: {exc}") from exc


def _print_report(report: Report, as_json: bool) -> int:
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for check in report.checks:
            print(f"[{check.status}] {check.name}: {check.detail}")
        print("VERIFIED" if report.ok else "NOT VERIFIED")
    return 0 if report.ok else 1


def cmd_keygen(args: argparse.Namespace) -> int:
    path = Path(args.out)
    if path.exists() and not args.force:
        raise CliError(f"{path} exists; use --force to overwrite it")
    key = SigningKey.generate(args.name)
    key.save(path)
    print(key.key_id)
    return 0


def cmd_key_id(args: argparse.Namespace) -> int:
    print(_key_id(args.key))
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    issuer = _signing_key(args.issuer_key)
    parent = _read_json(Path(args.parent)) if args.parent else None
    try:
        scope = Scope(actions=args.action, resources=args.resource)
        delegation = issue_delegation(
            issuer,
            _key_id(args.subject),
            scope,
            expires_in=parse_duration(args.expires_in),
            may_delegate=args.may_delegate,
            parent=parent,
            subject_name=args.subject_name,
        )
    except (DelegationError, ValueError) as exc:
        raise CliError(str(exc)) from exc
    text = json.dumps(delegation, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_policy_check(args: argparse.Namespace) -> int:
    policy = _policy(args)
    assert policy is not None
    decision = policy.evaluate(args.action, args.resource)
    print(json.dumps(to_document(decision), indent=2))
    return 0


def cmd_proof_verify(args: argparse.Namespace) -> int:
    anchors, gateways = _trust(args)
    receipt = _read_json(Path(args.receipt))
    report = verify_receipt(receipt, trust_anchors=anchors, gateways=gateways, policy=_policy(args))
    return _print_report(report, args.json)


def cmd_ledger_verify(args: argparse.Namespace) -> int:
    anchors, gateways = _trust(args)
    path = Path(args.ledger)
    if not path.exists():
        raise CliError(f"{path}: file not found")
    try:
        ledger = Ledger(path)
    except LedgerError as exc:
        raise CliError(str(exc)) from exc
    report = verify_ledger(ledger, trust_anchors=anchors, gateways=gateways, policy=_policy(args))
    return _print_report(report, args.json)


def cmd_schema(args: argparse.Namespace) -> int:
    for path in write_schemas(Path(args.out)):
        print(path)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    token = os.environ.get("OAT_OMF_TOKEN")
    try:
        ok = run_demo(Path(args.out), omf_url=args.omf_url, omf_token=token)
    except FileExistsError as exc:
        raise CliError(str(exc)) from exc
    return 0 if ok else 1


def _anchors(args: argparse.Namespace) -> list[str]:
    anchors = [_key_id(v) for v in args.anchor]
    if args.trust:
        data = _read_json(Path(args.trust))
        anchors += [_key_id(v) for v in data.get("trust_anchors", [])]
    if not anchors:
        raise CliError("give at least one --anchor (or --trust FILE)")
    return anchors


def _local_gateway(args: argparse.Namespace) -> Gateway:
    policy = _policy(args)
    if policy is None:
        raise CliError("give the gateway's --policy FILE")
    try:
        ledger = Ledger(args.ledger)
    except LedgerError as exc:
        raise CliError(str(exc)) from exc
    return Gateway(
        _signing_key(args.gateway_key), policy, trust_anchors=_anchors(args), ledger=ledger
    )


def _api_token(generate: bool) -> str:
    token = os.environ.get(TOKEN_ENV, "")
    if token:
        return token
    if not generate:
        raise CliError(f"set {TOKEN_ENV} to the token of the `oat serve` API")
    token = secrets.token_urlsafe(32)
    print(f"oat serve: no {TOKEN_ENV} set; this run's API token is {token}", file=sys.stderr)
    return token


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import GatewayService, make_server, serve

    gateway = _local_gateway(args)
    try:
        approval_timeout = parse_duration(args.approval_timeout)
        outcome_timeout = parse_duration(args.outcome_timeout)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    service = GatewayService(
        gateway,
        gateways=[_key_id(v) for v in args.gateway],
        approver_key=_signing_key(args.approver_key) if args.approver_key else None,
        approval_timeout=approval_timeout,
        outcome_timeout=outcome_timeout,
    )
    try:
        server = make_server(
            service,
            token=_api_token(generate=True),
            host=args.host,
            port=args.port,
            cors_origin=args.cors_origin,
        )
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot listen on {args.host}:{args.port}: {exc}") from exc
    print(
        f"oat serve: gateway {gateway.key.key_id[:24]}... on http://{args.host}:{args.port}"
        f" (ledger {args.ledger}, {len(gateway.ledger)} receipts)",
        file=sys.stderr,
    )
    with contextlib.suppress(KeyboardInterrupt):
        serve(server, service)
    return 0


def cmd_mcp_proxy(args: argparse.Namespace) -> int:
    from .client import GatewayClient
    from .mcp_proxy import Authorizer, LocalAuthorizer, McpProxy, RemoteAuthorizer

    upstream = args.upstream[1:] if args.upstream[:1] == ["--"] else args.upstream
    chain = _read_json(Path(args.chain))
    if not isinstance(chain, list):
        raise CliError(f"{args.chain}: expected a JSON list of delegations")
    authorizer: Authorizer
    if args.gateway_url:
        try:
            client = GatewayClient(args.gateway_url, _api_token(generate=False))
            wait = parse_duration(args.approval_wait)
        except ValueError as exc:
            raise CliError(str(exc)) from exc
        authorizer = RemoteAuthorizer(
            client,
            approval_wait=wait,
            on_pending=lambda a: print(
                f"oat mcp-proxy: {a['action']} on {a['resource']} awaits approval ({a['id']})",
                file=sys.stderr,
            ),
        )
    elif args.gateway_key:
        authorizer = LocalAuthorizer(_local_gateway(args))
    else:
        raise CliError("give --gateway-url (an `oat serve` API) or --gateway-key (local)")
    try:
        proxy = McpProxy(
            upstream,
            agent=_signing_key(args.agent_key),
            delegation_chain=chain,
            authorizer=authorizer,
            server_name=args.server,
            resource_argument=args.resource_arg,
            references=args.reference,
        )
        return proxy.run()
    except (ValueError, OSError) as exc:
        raise CliError(str(exc)) from exc


def _add_gateway_options(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument(
        "--gateway-key", required=required, metavar="FILE", help="the gateway's signing key"
    )
    parser.add_argument("--policy", required=required, metavar="FILE", help="policy YAML")
    parser.add_argument(
        "--anchor",
        action="append",
        default=[],
        metavar="KEY",
        help="trusted root key id or key file (repeatable)",
    )
    parser.add_argument("--trust", metavar="FILE", help="JSON file with 'trust_anchors'")
    parser.add_argument(
        "--ledger", default="oat-ledger.jsonl", metavar="FILE", help="receipt ledger (JSON Lines)"
    )


def _add_trust_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--anchor",
        action="append",
        default=[],
        metavar="KEY",
        help="trusted root key id or key file (repeatable)",
    )
    parser.add_argument(
        "--gateway",
        action="append",
        default=[],
        metavar="KEY",
        help="trusted gateway key id or key file (repeatable)",
    )
    parser.add_argument(
        "--trust", metavar="FILE", help="JSON file with 'trust_anchors' and 'gateways' key id lists"
    )
    parser.add_argument(
        "--policy", metavar="FILE", help="policy YAML; also re-checks each policy decision"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oat", description="OpenAgentTrust: verifiable authority for AI agent actions."
    )
    parser.add_argument("--version", action="version", version=f"oat {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 key file and print its key id")
    p.add_argument("out", help="where to write the private key (JWK)")
    p.add_argument("--name", help="human-readable label stored with the key")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("key-id", help="print the key id of a key file")
    p.add_argument("key")
    p.set_defaults(func=cmd_key_id)

    p = sub.add_parser("delegate", help="issue a signed delegation")
    p.add_argument("--issuer-key", required=True, metavar="FILE")
    p.add_argument("--subject", required=True, metavar="KEY", help="key id or key file")
    p.add_argument("--subject-name")
    p.add_argument("--action", action="append", required=True, metavar="PATTERN")
    p.add_argument("--resource", action="append", required=True, metavar="PATTERN")
    p.add_argument("--expires-in", default="24h", metavar="DURATION")
    p.add_argument("--may-delegate", action="store_true")
    p.add_argument("--parent", metavar="FILE", help="delegation the issuer re-delegates from")
    p.add_argument("--out", metavar="FILE")
    p.set_defaults(func=cmd_delegate)

    policy = sub.add_parser("policy", help="policy tools").add_subparsers(
        dest="policy_command", required=True
    )
    p = policy.add_parser("check", help="evaluate a policy for one action")
    p.add_argument("policy")
    p.add_argument("--action", required=True)
    p.add_argument("--resource", required=True)
    p.set_defaults(func=cmd_policy_check)

    proof = sub.add_parser("proof", help="receipt tools").add_subparsers(
        dest="proof_command", required=True
    )
    p = proof.add_parser("verify", help="verify one receipt")
    p.add_argument("receipt")
    _add_trust_options(p)
    p.set_defaults(func=cmd_proof_verify)

    ledger = sub.add_parser("ledger", help="ledger tools").add_subparsers(
        dest="ledger_command", required=True
    )
    p = ledger.add_parser("verify", help="verify every receipt and the hash chain")
    p.add_argument("ledger")
    _add_trust_options(p)
    p.set_defaults(func=cmd_ledger_verify)

    p = sub.add_parser("schema", help="write the AgentProof JSON Schemas")
    p.add_argument("--out", default="protocol/schemas/v0.1")
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("demo", help="run the end-to-end demo")
    p.add_argument("--out", default="oat-demo", help="empty or new output directory")
    p.add_argument("--omf-url", help="Open Model Fabric base URL (token from OAT_OMF_TOKEN)")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser(
        "serve",
        help="run the gateway as an HTTP API (token from " + TOKEN_ENV + ")",
        description="Serve the gateway over HTTP: submit actions, approve them, browse and "
        f"verify receipts. Clients authenticate with the bearer token in {TOKEN_ENV}; "
        "if it is unset, a random token is generated and printed.",
    )
    _add_gateway_options(p, required=True)
    p.add_argument(
        "--gateway",
        action="append",
        default=[],
        metavar="KEY",
        help="another gateway whose receipts /v1/verify should trust (repeatable)",
    )
    p.add_argument(
        "--approver-key",
        metavar="FILE",
        help="sign approvals made through the API with this key (it must be a policy approver)",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--cors-origin", metavar="URL", help="browser origin allowed to call the API")
    p.add_argument("--approval-timeout", default="10m", metavar="DURATION")
    p.add_argument("--outcome-timeout", default="10m", metavar="DURATION")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser(
        "mcp-proxy",
        help="enforce policy on an MCP server's tools/call over stdio",
        description="Run an MCP server behind the gateway: every tools/call is signed as "
        "the agent, decided by the policy (and approved, if required) and receipted. "
        "Example: oat mcp-proxy --agent-key agent.json --chain chain.json --server fs "
        "--gateway-url http://127.0.0.1:8787 -- npx @modelcontextprotocol/server-filesystem .",
    )
    p.add_argument("--agent-key", required=True, metavar="FILE")
    p.add_argument("--chain", required=True, metavar="FILE", help="delegation chain (JSON list)")
    p.add_argument("--server", required=True, metavar="NAME", help="actions are mcp.NAME.<tool>")
    p.add_argument(
        "--resource-arg",
        metavar="ARG",
        help="tool argument used as the resource (default: mcp:NAME)",
    )
    p.add_argument(
        "--reference",
        action="append",
        default=[],
        metavar="URI",
        help="reference URI added to every signed request, e.g. github:pr:owner/repo#12",
    )
    p.add_argument("--gateway-url", metavar="URL", help=f"an `oat serve` API ({TOKEN_ENV})")
    p.add_argument("--approval-wait", default="10m", metavar="DURATION")
    _add_gateway_options(p, required=False)
    p.add_argument("upstream", nargs=argparse.REMAINDER, help="-- MCP server command")
    p.set_defaults(func=cmd_mcp_proxy)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"oat: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
