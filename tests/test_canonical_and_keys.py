from __future__ import annotations

import json
from pathlib import Path

import pytest

from openagenttrust.canonical import CanonicalizationError, canonical_bytes, digest
from openagenttrust.keys import InvalidKeyError, PublicKey, SigningKey, b64u_decode
from openagenttrust.signing import sign, signing_input, verify

VECTORS = Path(__file__).parents[1] / "protocol" / "test-vectors" / "v0.1"


def test_canonical_form_sorts_keys_and_drops_whitespace() -> None:
    assert (
        canonical_bytes({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()
    )


@pytest.mark.parametrize(
    "value",
    [1.5, {"x": float("nan")}, 2**53, {1: "non-string key"}, {"ключ": 1}, {"s": "\ud800"}, b"x"],
)
def test_values_outside_the_canonical_subset_are_rejected(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_digest_format() -> None:
    assert digest({}) == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"


def test_key_roundtrip_through_jwk_file(tmp_path: Path) -> None:
    key = SigningKey.generate("alice")
    key.save(tmp_path / "k.json")
    loaded = SigningKey.load(tmp_path / "k.json")
    assert loaded.key_id == key.key_id
    assert loaded.name == "alice"
    assert PublicKey.from_key_id(key.key_id).verify(key.sign(b"m"), b"m")


def test_jwk_with_mismatched_public_part_is_rejected() -> None:
    jwk = SigningKey.generate().to_jwk()
    jwk["x"] = SigningKey.generate().to_jwk()["x"]
    with pytest.raises(InvalidKeyError):
        SigningKey.from_jwk(jwk)


@pytest.mark.parametrize("text", ["AAA=", "A+B/", "AB"])
def test_strict_base64url(text: str) -> None:
    with pytest.raises(InvalidKeyError):
        b64u_decode(text)


def test_signature_covers_every_member_except_signature() -> None:
    key = SigningKey.generate()
    signed = sign({"type": "t", "a": 1}, key)
    assert verify(signed, key.key_id)
    assert not verify({**signed, "a": 2}, key.key_id)
    assert not verify({**signed, "type": "other"}, key.key_id)
    assert not verify(signed, SigningKey.generate().key_id)
    assert not verify({**signed, "signature": None}, key.key_id)


def test_published_signature_vector() -> None:
    """Other implementations must reproduce these bytes exactly."""
    vector = json.loads((VECTORS / "signature.json").read_text(encoding="utf-8"))
    key = SigningKey.from_jwk(vector["key"])
    assert key.key_id == vector["key_id"]
    assert signing_input(vector["document"]).hex() == vector["signing_input_hex"]
    assert sign(vector["document"], key)["signature"] == vector["signature"]
    assert digest(vector["document"]) == vector["digest"]
