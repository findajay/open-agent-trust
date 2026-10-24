"""``oat``: the OpenAgentTrust command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .delegation import DelegationError, issue_delegation
from .keys import InvalidKeyError, PublicKey, SigningKey
from .ledger import Ledger, LedgerError
from .models import Scope, to_document
from .policy import Policy, PolicyError
from .schemas import write_schemas
from .timeutil import parse_duration
from .verify import Report, verify_ledger, verify_receipt


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
