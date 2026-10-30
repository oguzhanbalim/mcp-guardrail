"""Real SDK client -> real proxy server -> real upstream server, all in one process."""

from __future__ import annotations

import anyio
import mcp_types as types
import pytest
from mcp import Client
from mcp.server import MCPServer

from conftest import read_log
from mcp_guardrail import AuditLog, GuardrailProxy
from mcp_guardrail.approval import ApprovalRequest, deny_all
from mcp_guardrail.demo_server import build_demo_server
from mcp_guardrail.policy import load_policy, parse_policy

pytestmark = pytest.mark.anyio


class Recorder:
    """An approver that records what it was shown."""

    def __init__(self, answer: bool = True) -> None:
        self.answer = answer
        self.seen: list[ApprovalRequest] = []

    async def __call__(self, request: ApprovalRequest) -> bool:
        self.seen.append(request)
        return self.answer


def text(result: types.CallToolResult) -> str:
    return result.content[0].text


@pytest.fixture
def harness(tmp_path):
    """Yield a function that opens a client wired through a proxy."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def connect(policy=None, approver=deny_all, upstream_server=None):
        policy = policy or load_policy("examples/policy.yaml")
        audit = AuditLog(tmp_path / "audit.jsonl")
        async with Client(upstream_server or build_demo_server()) as upstream:
            proxy = GuardrailProxy(policy, upstream, audit, approver)
            async with Client(proxy.server()) as client:
                yield client
        audit.close()

    connect.log = tmp_path / "audit.jsonl"
    return connect


async def test_tool_list_hides_what_the_policy_does_not_name(harness):
    async with harness() as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert names == {"read_file", "write_file", "issue_refund"}


async def test_allowed_call_is_forwarded_and_logged(harness):
    async with harness() as client:
        result = await client.call_tool("read_file", {"path": "/workspace/notes.txt"})
    assert not result.is_error
    assert "synthetic demo note" in text(result)
    records = read_log(harness.log)
    assert [r["event"] for r in records] == ["decision", "result"]
    assert records[0]["verdict"] == "allow"
    assert records[1]["outcome"] == "ok"
    assert records[0]["call_id"] == records[1]["call_id"]


async def test_hidden_tool_called_directly_is_denied_and_never_runs(harness):
    async with harness() as client:
        denied = await client.call_tool("delete_everything", {})
    assert denied.is_error
    assert "not in the policy" in text(denied)
    assert [r["event"] for r in read_log(harness.log)] == ["decision"]


async def test_traversal_does_not_reach_the_server(harness):
    async with harness() as client:
        denied = await client.call_tool("read_file", {"path": "/workspace/../etc/secrets"})
    assert denied.is_error
    assert "not for agents" not in text(denied)
    assert "resolves outside" in text(denied)


async def test_approved_call_runs_and_records_approval(harness):
    human = Recorder(answer=True)
    async with harness(approver=human) as client:
        result = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 40})
    assert "refunded 40" in text(result)
    assert len(human.seen) == 1
    assert human.seen[0].arguments == {"order_id": "ORD-1", "amount": 40}
    events = [(r["event"], r.get("verdict") or r.get("outcome")) for r in read_log(harness.log)]
    assert events == [("decision", "needs_approval"), ("approval", "approved"), ("result", "ok")]


async def test_rejected_call_never_runs(harness):
    server = MCPServer("spy")
    calls = []

    @server.tool()
    def issue_refund(order_id: str, amount: float) -> str:
        calls.append(order_id)
        return "refunded"

    async with harness(approver=Recorder(answer=False), upstream_server=server) as client:
        refused = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 40})
    assert refused.is_error
    assert "rejected" in text(refused)
    assert calls == []
    assert [r["event"] for r in read_log(harness.log)] == ["decision", "approval"]


async def test_over_limit_is_denied_without_bothering_the_human(harness):
    human = Recorder()
    async with harness(approver=human) as client:
        denied = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 5000})
    assert denied.is_error
    assert human.seen == []


async def test_default_approver_fails_closed(harness):
    async with harness() as client:
        refused = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 1})
    assert refused.is_error


async def test_approver_exception_counts_as_rejection(harness):
    async def broken(request: ApprovalRequest) -> bool:
        raise RuntimeError("approver crashed")

    async with harness(approver=broken) as client:
        refused = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 1})
    assert refused.is_error
    assert "approver_error: RuntimeError" in text(refused)


async def test_approval_timeout_counts_as_rejection(harness):
    async def never(request: ApprovalRequest) -> bool:
        await anyio.sleep(60)
        return True

    p = parse_policy(
        {
            "version": 1,
            "approval_timeout_seconds": 0.05,
            "tools": {"delete_everything": {"approval": True}},
        }
    )
    async with harness(policy=p, approver=never) as client:
        refused = await client.call_tool("delete_everything", {})
    assert refused.is_error
    assert "timeout" in text(refused)


async def test_truthy_approver_result_is_not_approval(harness):
    async def sloppy(request: ApprovalRequest):
        return "no"

    async with harness(approver=sloppy) as client:
        refused = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 1})
    assert refused.is_error


async def test_redacted_arguments_never_reach_the_log(harness):
    async with harness(approver=Recorder()) as client:
        await client.call_tool(
            "write_file", {"path": "/workspace/a", "content": "super-secret-value"}
        )
    raw = harness.log.read_text(encoding="utf-8")
    assert "super-secret-value" not in raw
    assert "[redacted]" in raw


async def test_unwritable_audit_log_blocks_the_call(tmp_path):
    policy = load_policy("examples/policy.yaml")
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.close()
    calls = []
    server = MCPServer("spy")

    @server.tool()
    def read_file(path: str) -> str:
        calls.append(path)
        return "contents"

    async with Client(server) as upstream:
        proxy = GuardrailProxy(policy, upstream, audit)
        async with Client(proxy.server()) as client:
            refused = await client.call_tool("read_file", {"path": "/workspace/a"})
    assert refused.is_error
    assert "audit log" in text(refused)
    assert calls == []


async def test_tool_error_is_passed_through_and_logged(harness):
    server = MCPServer("bad")

    @server.tool()
    def read_file(path: str) -> str:
        raise ValueError("disk on fire")

    async with harness(upstream_server=server) as client:
        result = await client.call_tool("read_file", {"path": "/workspace/a"})
    assert result.is_error
    assert read_log(harness.log)[-1]["outcome"] == "tool_error"


async def test_server_that_contradicts_read_only_claim_is_blocked(harness):
    server = MCPServer("liar")
    calls = []

    @server.tool(annotations=types.ToolAnnotations(destructive_hint=True))
    def read_file(path: str) -> str:
        calls.append(path)
        return "deleted"

    async with harness(upstream_server=server) as client:
        names = [tool.name for tool in (await client.list_tools()).tools]
        refused = await client.call_tool("read_file", {"path": "/workspace/a"})
    assert "read_file" not in names
    assert refused.is_error
    assert "destructiveHint" in text(refused)
    assert calls == []


async def test_conflict_is_caught_even_if_client_never_lists_tools(harness):
    server = MCPServer("liar")

    @server.tool(annotations=types.ToolAnnotations(read_only_hint=False))
    def read_file(path: str) -> str:
        return "wrote something"

    async with harness(upstream_server=server) as client:
        refused = await client.call_tool("read_file", {"path": "/workspace/a"})
    assert refused.is_error
    assert "readOnlyHint" in text(refused)


async def test_output_schema_tool_results_survive_the_proxy(harness):
    async with harness() as client:
        result = await client.call_tool("read_file", {"path": "/workspace/notes.txt"})
    assert result.structured_content == {"result": "synthetic demo note\n"}
