"""Append-only, hash-chained receipt log (JSON Lines).

Each receipt's ``prev`` member is the digest of the receipt before it, so removing,
reordering or editing any entry breaks the chain for every later receipt. The ledger
itself does not verify signatures; use :func:`openagenttrust.verify.verify_ledger`.

One process should own a ledger file at a time.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, digest


class LedgerError(ValueError):
    """A receipt does not extend the ledger."""


class Ledger:
    def __init__(self, path: str | Path | None = None) -> None:
        """Open (or create) the ledger at ``path``; ``None`` keeps it in memory."""
        path = Path(path) if path is not None else None
        self.path = path
        self._receipts: list[dict[str, Any]] = []
        self._request_digests: set[str] = set()
        self.head: str | None = None
        if path is not None and path.exists():
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    receipt = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LedgerError(f"{path}:{line_number}: not JSON") from exc
                self._remember(receipt)

    def _remember(self, receipt: dict[str, Any]) -> None:
        self._receipts.append(receipt)
        self._request_digests.add(str(receipt.get("request_digest")))
        self.head = digest(receipt)

    def contains_request(self, request_digest: str) -> bool:
        return request_digest in self._request_digests

    def append(self, receipt: dict[str, Any]) -> None:
        if receipt.get("prev") != self.head:
            raise LedgerError("receipt.prev does not point at the current ledger head")
        if self.contains_request(str(receipt.get("request_digest"))):
            raise LedgerError("a receipt for this request is already in the ledger")
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("ab") as handle:
                handle.write(canonical_bytes(receipt) + b"\n")
        self._remember(receipt)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(list(self._receipts))

    def __len__(self) -> int:
        return len(self._receipts)
