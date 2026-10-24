"""Regenerate protocol/test-vectors (deterministic: fixed key, fixed document)."""

from __future__ import annotations

import json
from pathlib import Path

from openagenttrust.canonical import digest
from openagenttrust.keys import SigningKey, b64u_encode
from openagenttrust.signing import sign, signing_input

OUT = Path(__file__).parents[1] / "protocol" / "test-vectors" / "v0.1"
# RFC 8032, section 7.1, TEST 1 secret key.
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def main() -> None:
    key = SigningKey.from_jwk({"kty": "OKP", "crv": "Ed25519", "d": b64u_encode(SEED)})
    document = {
        "type": "agentproof.delegation/v0.1",
        "id": "dlg_vector_1",
        "issuer": key.key_id,
        "subject": key.key_id,
        "subject_name": "Ünïcødé agent",
        "scope": {"actions": ["sensor.*"], "resources": ["plant-7/*"]},
        "may_delegate": False,
        "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-02T00:00:00Z",
        "parent": None,
        "signature": None,
    }
    vector = {
        "description": (
            "Ed25519 signature over the canonical form of a delegation (RFC 8032 test key 1)"
        ),
        "key": {"kty": "OKP", "crv": "Ed25519", "d": b64u_encode(SEED)},
        "key_id": key.key_id,
        "document": document,
        "signing_input_hex": signing_input(document).hex(),
        "signature": sign(document, key)["signature"],
        "digest": digest(document),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "signature.json").write_text(
        json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    main()
