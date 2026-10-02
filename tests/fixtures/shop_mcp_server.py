"""Minimal real stdio MCP server (newline-delimited JSON-RPC)."""
import json, sys
TOOLS = [
    {"name": "list_orders", "description": "List orders", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "refund_order", "description": "Refund an order", "inputSchema": {"type": "object", "properties": {"order": {"type": "string"}, "amount": {"type": "number"}}}},
    {"name": "export_all_customers", "description": "Bulk export", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "delete_doc", "description": "Delete a document", "inputSchema": {"type": "object", "properties": {"doc": {"type": "string"}}}},
]
for line in sys.stdin:
    msg = json.loads(line)
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        continue
    if method == "initialize":
        res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "shop", "version": "1"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg["params"]
        res = {"content": [{"type": "text", "text": f"shop ran {p['name']} {json.dumps(p.get('arguments'))}"}]}
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n"); sys.stdout.flush()
