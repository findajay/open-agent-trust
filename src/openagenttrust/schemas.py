"""JSON Schemas for the AgentProof wire format, generated from the models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import DOCUMENT_TYPES

SCHEMA_BASE = (
    "https://raw.githubusercontent.com/findajay/open-agent-trust/main/protocol/schemas/v0.1/"
)


def schema_files() -> dict[str, dict[str, Any]]:
    files = {}
    for type_name, model in DOCUMENT_TYPES.items():
        kind = type_name.split(".", 1)[1].split("/", 1)[0]
        schema = model.model_json_schema(mode="validation")
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"{SCHEMA_BASE}{kind}.schema.json",
            **schema,
        }
        files[f"{kind}.schema.json"] = schema
    return files


def render(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def write_schemas(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, schema in schema_files().items():
        path = directory / name
        path.write_text(render(schema), encoding="utf-8", newline="\n")
        written.append(path)
    return written
