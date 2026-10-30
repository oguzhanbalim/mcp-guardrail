"""The MCP proxy: a server to the client, a client to the upstream server.

Only tools are proxied. Resources, prompts and sampling are not forwarded, so a
capability this module does not know about cannot slip past the policy.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import anyio
import mcp_types as types
from mcp import Client
from mcp.server import Server, ServerRequestContext

from mcp_guardrail.approval import ApprovalRequest, Approver, deny_all
from mcp_guardrail.audit import AuditLog
from mcp_guardrail.policy import Policy, Verdict

logger = logging.getLogger("mcp_guardrail")


def _error(message: str) -> types.CallToolResult:
    # Denials are tool errors, not protocol errors, so the model can read them and adapt.
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


def read_only_conflict(tool: types.Tool) -> str | None:
    """Explain why a tool's own annotations contradict a read-only claim in the policy.

    Annotations are untrusted hints, so a clean tool proves nothing. But a server
    that says a tool writes should be believed over a policy that says it does not.
    """
    hints = tool.annotations
    if hints is None:
        return None
    if hints.read_only_hint is False:
        return "the server declares readOnlyHint=false"
    if hints.destructive_hint is True and hints.read_only_hint is not True:
        return "the server declares destructiveHint=true"
    return None


async def list_all_tools(upstream: Client) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await upstream.list_tools(cursor=cursor)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


class GuardrailProxy:
    def __init__(
        self,
        policy: Policy,
        upstream: Client,
        audit: AuditLog,
        approver: Approver = deny_all,
    ) -> None:
        self.policy = policy
        self.upstream = upstream
        self.audit = audit
        self.approver = approver
        self._conflicts: dict[str, str] | None = None

    def server(self) -> Server[Any]:
        return Server(
            "mcp-guardrail",
            on_list_tools=self._on_list_tools,
            on_call_tool=self._on_call_tool,
        )

    async def _refresh(self) -> list[types.Tool]:
        tools = await list_all_tools(self.upstream)
        self._conflicts = {}
        for tool in tools:
            rule = self.policy.tools.get(tool.name)
            conflict = read_only_conflict(tool) if rule and rule.read_only else None
            if conflict:
                self._conflicts[tool.name] = conflict
        return tools

    async def _on_list_tools(
        self, ctx: ServerRequestContext[Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tools = await self._refresh()
        visible = [
            tool
            for tool in tools
            if self.policy.exposes(tool.name) and tool.name not in (self._conflicts or {})
        ]
        return types.ListToolsResult(tools=visible)

    async def _on_call_tool(
        self, ctx: ServerRequestContext[Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await self.handle_call(params.name, params.arguments or {})

    async def handle_call(self, tool: str, arguments: dict[str, Any]) -> types.CallToolResult:
        call_id = uuid.uuid4().hex
        logged_args = self.policy.redacted(tool, arguments)

        decision = self.policy.decide(tool, arguments)
        if decision.verdict is not Verdict.DENY:
            if self._conflicts is None:
                try:
                    await self._refresh()
                except Exception as exc:
                    return self._refuse(call_id, tool, logged_args, f"upstream unavailable: {exc}")
            conflict = (self._conflicts or {}).get(tool)
            if conflict:
                return self._refuse(
                    call_id, tool, logged_args, f"policy says read-only but {conflict}"
                )

        # Write ahead: the decision reaches disk before anything happens. If it cannot
        # be recorded, nothing runs, so there is never an unaudited forwarded call.
        try:
            self.audit.write(
                "decision",
                call_id,
                tool=tool,
                args=logged_args,
                verdict=decision.verdict.value,
                reason=decision.reason,
            )
        except OSError as exc:
            logger.error("audit write failed, refusing call: %s", exc)
            return _error("mcp-guardrail: call refused because the audit log is not writable")

        if decision.verdict is Verdict.DENY:
            return _error(f"mcp-guardrail: denied: {decision.reason}")

        if decision.verdict is Verdict.NEEDS_APPROVAL:
            request = ApprovalRequest(call_id, tool, arguments, decision.reason)
            outcome = await self._ask_human(request)
            try:
                self.audit.write("approval", call_id, tool=tool, outcome=outcome)
            except OSError as exc:
                logger.error("audit write failed, refusing call: %s", exc)
                return _error("mcp-guardrail: call refused because the audit log is not writable")
            if outcome != "approved":
                return _error(f"mcp-guardrail: not approved ({outcome})")

        return await self._forward(call_id, tool, arguments)

    def _refuse(
        self, call_id: str, tool: str, logged_args: dict[str, Any], reason: str
    ) -> types.CallToolResult:
        try:
            self.audit.write(
                "decision", call_id, tool=tool, args=logged_args, verdict="deny", reason=reason
            )
        except OSError as exc:
            logger.error("audit write failed: %s", exc)
        return _error(f"mcp-guardrail: denied: {reason}")

    async def _ask_human(self, request: ApprovalRequest) -> str:
        with anyio.move_on_after(self.policy.approval_timeout_seconds):
            try:
                approved = await self.approver(request)
            except Exception as exc:
                return f"approver_error: {type(exc).__name__}"
            return "approved" if approved is True else "rejected"
        return "timeout"

    async def _forward(
        self, call_id: str, tool: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        started = time.perf_counter()
        try:
            result = await self.upstream.call_tool(tool, arguments)
        except Exception as exc:
            self._record_result(call_id, tool, "upstream_error", started, type(exc).__name__)
            return _error(f"mcp-guardrail: upstream call failed: {type(exc).__name__}")
        self._record_result(call_id, tool, "tool_error" if result.is_error else "ok", started)
        return types.CallToolResult(
            content=result.content,
            structured_content=result.structured_content,
            is_error=result.is_error,
        )

    def _record_result(
        self, call_id: str, tool: str, outcome: str, started: float, error: str | None = None
    ) -> None:
        fields: dict[str, Any] = {"duration_ms": round((time.perf_counter() - started) * 1000, 1)}
        if error:
            fields["error"] = error
        try:
            self.audit.write("result", call_id, tool=tool, outcome=outcome, **fields)
        except OSError as exc:
            # The call already happened; failing it now would misreport what was done.
            logger.error("audit write failed after call %s: %s", call_id, exc)
