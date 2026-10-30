"""Human approval back ends.

The proxy's stdin and stdout carry the MCP protocol, so it cannot prompt on them.
An approver is any async callable returning True to approve. Anything else
(False, an exception, a timeout) counts as rejected.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import anyio
import anyio.to_thread


@dataclass(frozen=True)
class ApprovalRequest:
    call_id: str
    tool: str
    arguments: dict[str, Any]
    reason: str


Approver = Callable[[ApprovalRequest], Awaitable[bool]]


async def deny_all(request: ApprovalRequest) -> bool:
    """The default: with no human wired up, nothing that needs one can run."""
    return False


def format_prompt(request: ApprovalRequest) -> str:
    """Render a request for a terminal.

    The arguments are chosen by the agent. ``ensure_ascii`` escapes control characters,
    so ANSI sequences in an argument cannot rewrite what the human sees.
    """
    return (
        f"\n[mcp-guardrail] approval needed\n"
        f"  tool: {json.dumps(request.tool, ensure_ascii=True)}\n"
        f"  args: {json.dumps(request.arguments, ensure_ascii=True, sort_keys=True)}\n"
        f"Approve? Type 'yes' to approve: "
    )


def tty_approver(device: str = "/dev/tty") -> Approver:
    """Prompt on the controlling terminal. No terminal means rejected."""

    def ask(request: ApprovalRequest) -> bool:
        # Two handles: a terminal is not seekable, so it cannot be opened in "r+" text mode.
        with open(device, encoding="utf-8") as answer, open(device, "w", encoding="utf-8") as out:
            out.write(format_prompt(request))
            out.flush()
            return answer.readline().strip().lower() == "yes"

    async def approve(request: ApprovalRequest) -> bool:
        return await anyio.to_thread.run_sync(ask, request, abandon_on_cancel=True)

    return approve


def command_approver(command: str) -> Approver:
    """Run a command with the request as JSON on stdin. Exit status 0 approves."""
    argv = shlex.split(command)

    async def approve(request: ApprovalRequest) -> bool:
        payload = json.dumps(
            {"call_id": request.call_id, "tool": request.tool, "arguments": request.arguments}
        )
        result = await anyio.run_process(
            argv,
            input=payload.encode("utf-8"),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0

    return approve


def approver_from_spec(spec: str) -> Approver:
    """Build an approver from the CLI value: ``deny``, ``tty`` or ``cmd:<command>``."""
    if spec == "deny":
        return deny_all
    if spec == "tty":
        return tty_approver()
    if spec.startswith("cmd:") and spec[4:].strip():
        return command_approver(spec[4:])
    raise ValueError(f"unknown approver {spec!r}; expected deny, tty or cmd:<command>")
