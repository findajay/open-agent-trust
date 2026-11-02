"""A minimal stdio MCP server for the proxy tests: echoes tool calls back."""

from __future__ import annotations

import json
import sys


def reply(message_id: object, result: object) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    message = json.loads(line)
    method, message_id = message.get("method"), message.get("id")
    if message_id is None:
        continue  # notification
    if method == "initialize":
        reply(message_id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}})
    elif method == "tools/list":
        reply(message_id, {"tools": [{"name": "read_file"}, {"name": "write_file"}]})
    elif method == "tools/call":
        params = message["params"]
        if params["name"] == "explode":
            reply(message_id, {"content": [{"type": "text", "text": "boom"}], "isError": True})
        else:
            text = json.dumps(params.get("arguments", {}), sort_keys=True)
            reply(
                message_id,
                {
                    "content": [{"type": "text", "text": f"{params['name']} {text}"}],
                    # A float: MCP results need not be in the canonical subset.
                    "structuredContent": {"score": 0.5},
                },
            )
    else:
        sys.stdout.write(
            json.dumps(
                {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": method}}
            )
            + "\n"
        )
        sys.stdout.flush()
