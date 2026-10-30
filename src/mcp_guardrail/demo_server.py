"""A small MCP server with an in-memory "filesystem" and a fake refund tool.

It touches no disk and no network. It exists so tests and the demo have something
real to proxy. Run it over stdio with ``python -m mcp_guardrail.demo_server``.
"""

from __future__ import annotations

import mcp_types as types
from mcp.server import MCPServer


def build_demo_server() -> MCPServer:
    server: MCPServer = MCPServer("guardrail-demo")
    files = {"/workspace/notes.txt": "synthetic demo note\n", "/etc/secrets": "not for agents\n"}
    refunds: list[tuple[str, float]] = []

    @server.tool(annotations=types.ToolAnnotations(read_only_hint=True))
    def read_file(path: str) -> str:
        """Read a file from the in-memory filesystem."""
        return files.get(path, "<no such file>")

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Write a file in the in-memory filesystem."""
        files[path] = content
        return f"wrote {len(content)} bytes to {path}"

    @server.tool()
    def issue_refund(order_id: str, amount: float) -> str:
        """Record a fake refund."""
        refunds.append((order_id, amount))
        return f"refunded {amount} on {order_id} ({len(refunds)} refund(s) so far)"

    @server.tool(annotations=types.ToolAnnotations(destructive_hint=True))
    def delete_everything() -> str:
        """Clear the in-memory filesystem."""
        files.clear()
        return "deleted everything"

    return server


if __name__ == "__main__":
    build_demo_server().run("stdio")
