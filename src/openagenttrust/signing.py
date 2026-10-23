"""Detached-member signatures over canonical JSON.

The signing input is ``b"agentproof/v0.1\\x00"`` followed by the canonical JSON of the
document with its ``signature`` member removed. Every document carries a ``type``
member, so one signature can never be replayed as a different kind of document.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .canonical import canonical_bytes
from .keys import InvalidKeyError, PublicKey, SigningKey, b64u_decode, b64u_encode

SIGNING_DOMAIN = b"agentproof/v0.1\x00"


def signing_input(document: Mapping[str, Any]) -> bytes:
    body = {key: value for key, value in document.items() if key != "signature"}
    if not isinstance(body.get("type"), str):
        raise ValueError("signed documents need a string 'type' member")
    return SIGNING_DOMAIN + canonical_bytes(body)


def sign(document: Mapping[str, Any], key: SigningKey) -> dict[str, Any]:
    """Return a copy of ``document`` with its ``signature`` member set."""
    signed = dict(document)
    signed["signature"] = {"alg": "Ed25519", "value": b64u_encode(key.sign(signing_input(signed)))}
    return signed


def verify(document: Mapping[str, Any], key_id: str) -> bool:
    """True if ``document`` carries a valid Ed25519 signature by ``key_id``."""
    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
        return False
    try:
        public = PublicKey.from_key_id(key_id)
        raw = b64u_decode(str(signature.get("value", "")))
        message = signing_input(document)
    except (InvalidKeyError, ValueError):
        return False
    return len(raw) == 64 and public.verify(raw, message)
