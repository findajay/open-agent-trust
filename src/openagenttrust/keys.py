"""Ed25519 keys and self-certifying key identifiers.

A key id is ``ed25519:`` followed by the base64url (unpadded) raw public key, so a
verifier needs nothing but the id to check a signature. Trust comes from configuration
(which ids are trust anchors, gateways or approvers), never from the key itself.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEY_ID_PREFIX = "ed25519:"
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


class InvalidKeyError(ValueError):
    """A key or key id is malformed."""


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Strict unpadded base64url decoding: rejects padding and non-canonical encodings."""
    if not _B64URL.fullmatch(text):
        raise InvalidKeyError("not unpadded base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyError("not unpadded base64url") from exc
    if b64u_encode(data) != text:
        raise InvalidKeyError("non-canonical base64url")
    return data


class PublicKey:
    """An Ed25519 verification key."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise InvalidKeyError("Ed25519 public keys are 32 bytes")
        self._raw = raw
        self._key = Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def from_key_id(cls, key_id: str) -> PublicKey:
        if not key_id.startswith(KEY_ID_PREFIX):
            raise InvalidKeyError(f"key id must start with {KEY_ID_PREFIX!r}")
        return cls(b64u_decode(key_id[len(KEY_ID_PREFIX) :]))

    @property
    def key_id(self) -> str:
        return KEY_ID_PREFIX + b64u_encode(self._raw)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self._key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class SigningKey:
    """An Ed25519 signing key, stored on disk as a private JWK (RFC 8037)."""

    def __init__(self, key: Ed25519PrivateKey, name: str | None = None) -> None:
        self._key = key
        self.name = name
        raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key = PublicKey(raw)

    @classmethod
    def generate(cls, name: str | None = None) -> SigningKey:
        return cls(Ed25519PrivateKey.generate(), name)

    @property
    def key_id(self) -> str:
        return self.public_key.key_id

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def to_jwk(self) -> dict[str, Any]:
        private = self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        jwk: dict[str, Any] = {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": self.key_id[len(KEY_ID_PREFIX) :],
            "d": b64u_encode(private),
            "kid": self.key_id,
        }
        if self.name:
            jwk["name"] = self.name
        return jwk

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> SigningKey:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise InvalidKeyError("expected an OKP/Ed25519 JWK")
        private = b64u_decode(str(jwk.get("d", "")))
        if len(private) != 32:
            raise InvalidKeyError("Ed25519 private keys are 32 bytes")
        key = cls(Ed25519PrivateKey.from_private_bytes(private), jwk.get("name"))
        if "x" in jwk and jwk["x"] != key.key_id[len(KEY_ID_PREFIX) :]:
            raise InvalidKeyError("JWK public part does not match its private part")
        return key

    def save(self, path: Path) -> None:
        """Write the key with owner-only permissions (where the OS supports it)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.to_jwk(), handle, indent=2)
            handle.write("\n")

    @classmethod
    def load(cls, path: Path) -> SigningKey:
        return cls.from_jwk(json.loads(path.read_text(encoding="utf-8")))
