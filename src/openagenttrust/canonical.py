"""Canonical JSON and digests for AgentProof documents.

AgentProof signs and hashes the canonical JSON form of a document. The form is a strict
subset of RFC 8785 (JSON Canonicalization Scheme) chosen so that every conforming
implementation produces identical bytes without a floating-point formatter:

* object member names are ASCII (so code-point and UTF-16 key ordering agree),
* numbers are integers within the IEEE-754 safe range (no floats),
* strings are valid Unicode (no lone surrogates).

Within that subset the output is byte-identical to RFC 8785.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
DIGEST_PREFIX = "sha256:"


class CanonicalizationError(ValueError):
    """A value is outside the canonical JSON subset AgentProof accepts."""


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool | str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"{path}: integer outside the safe range ±(2^53-1)")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floating-point numbers are not allowed")
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise CanonicalizationError(f"{path}: object member names must be ASCII strings")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"{path}: {type(value).__name__} is not a JSON value")


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``."""
    _check(value, "$")
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("strings must be valid Unicode") from exc


def digest(value: Any) -> str:
    """``sha256:<hex>`` digest of the canonical form of ``value``."""
    return DIGEST_PREFIX + hashlib.sha256(canonical_bytes(value)).hexdigest()
