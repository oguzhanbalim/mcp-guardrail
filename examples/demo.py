"""Drive client -> guardrail -> demo server in one process and print what happens.

The "human" is a function that approves everything except order ORD-999.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import anyio
from mcp import Client

from mcp_guardrail import AuditLog, GuardrailProxy, load_policy
from mcp_guardrail.approval import ApprovalRequest
from mcp_guardrail.demo_server import build_demo_server

CALLS = [
    ("read_file", {"path": "/workspace/notes.txt"}),
    ("read_file", {"path": "/workspace/../etc/secrets"}),
    ("write_file", {"path": "/workspace/out.txt", "content": "hello"}),
    ("issue_refund", {"order_id": "ORD-1", "amount": 40}),
    ("issue_refund", {"order_id": "ORD-1", "amount": 5000}),
    ("issue_refund", {"order_id": "ORD-999", "amount": 10}),
    ("delete_everything", {}),
]


async def fake_human(request: ApprovalRequest) -> bool:
    return request.arguments.get("order_id") != "ORD-999"


async def main() -> None:
    policy = load_policy(Path(__file__).with_name("policy.yaml"))
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp()) / "audit.jsonl"
    audit = AuditLog(log_path)
    async with Client(build_demo_server()) as upstream:
        proxy = GuardrailProxy(policy, upstream, audit, fake_human).server()
        async with Client(proxy) as client:
            listed = await client.list_tools()
            print("visible tools:", ", ".join(tool.name for tool in listed.tools))
            for tool, args in CALLS:
                result = await client.call_tool(tool, args)
                status = "ERROR" if result.is_error else "ok   "
                print(f"{status} {tool} {args}\n      -> {result.content[0].text}")
    audit.close()
    print(f"\naudit log: {log_path}")


if __name__ == "__main__":
    anyio.run(main)
