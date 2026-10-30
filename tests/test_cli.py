"""End to end over real stdio pipes: client -> `mcp-guardrail run` -> demo server."""

from __future__ import annotations

import json
import os
import pty
import stat
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from conftest import read_log
from mcp_guardrail.approval import ApprovalRequest, command_approver, format_prompt, tty_approver
from mcp_guardrail.cli import main

DEMO = [sys.executable, "-m", "mcp_guardrail.demo_server"]
POLICY = "examples/policy.yaml"


def proxy_params(audit: Path, approver: str = "deny") -> StdioServerParameters:
    args = ["-m", "mcp_guardrail", "run", "--policy", POLICY, "--audit", str(audit)]
    return StdioServerParameters(
        command=sys.executable, args=[*args, "--approver", approver, "--", *DEMO]
    )


def write_script(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.mark.anyio
async def test_stdio_end_to_end(tmp_path):
    audit = tmp_path / "audit.jsonl"
    async with Client(proxy_params(audit)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        ok = await client.call_tool("read_file", {"path": "/workspace/notes.txt"})
        denied = await client.call_tool("delete_everything", {})
        unapproved = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 1})
    assert names == {"read_file", "write_file", "issue_refund"}
    assert "synthetic demo note" in ok.content[0].text
    assert denied.is_error
    assert unapproved.is_error
    verdicts = [r["verdict"] for r in read_log(audit) if r["event"] == "decision"]
    assert verdicts == ["allow", "deny", "needs_approval"]


@pytest.mark.anyio
async def test_stdio_command_approver(tmp_path):
    seen = tmp_path / "seen.json"
    script = write_script(
        tmp_path / "approve.sh",
        f'cat > "{seen}"\ngrep -q ORD-1 "{seen}"',
    )
    audit = tmp_path / "audit.jsonl"
    async with Client(proxy_params(audit, f"cmd:{script}")) as client:
        ok = await client.call_tool("issue_refund", {"order_id": "ORD-1", "amount": 1})
        no = await client.call_tool("issue_refund", {"order_id": "ORD-2", "amount": 1})
    assert not ok.is_error
    assert no.is_error
    assert json.loads(seen.read_text())["arguments"]["order_id"] == "ORD-2"


@pytest.mark.parametrize(
    ("tool", "args", "code", "expected"),
    [
        ("read_file", '{"path": "/workspace/a"}', 0, "allow"),
        ("delete_everything", "{}", 1, "deny"),
        ("issue_refund", '{"order_id": "ORD-1", "amount": 5}', 2, "needs_approval"),
    ],
)
def test_explain(capsys, tool, args, code, expected):
    assert main(["explain", "--policy", POLICY, tool, args]) == code
    assert capsys.readouterr().out.startswith(expected)


def test_check_reports_exposure(capsys):
    assert main(["check", "--policy", POLICY, "--", *DEMO]) == 0
    out = capsys.readouterr().out
    assert "delete_everything" in out
    assert "hidden" in out


def test_check_flags_tools_missing_from_server(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ntools:\n  no_such_tool: {}\n", encoding="utf-8")
    assert main(["check", "--policy", str(policy), "--", *DEMO]) == 1
    assert "MISSING" in capsys.readouterr().out


def test_bad_policy_is_a_clean_error(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ntools:\n  t: {aproval: true}\n", encoding="utf-8")
    assert main(["explain", "--policy", str(policy), "t"]) == 3
    assert "aproval" in capsys.readouterr().err


def test_prompt_escapes_terminal_control_sequences():
    request = ApprovalRequest("id", "t\x1b[2J", {"note": "\x1b[1Aapproved already\r"}, "r")
    prompt = format_prompt(request)
    assert "\x1b" not in prompt
    assert "\r" not in prompt
    assert "\\u001b" in prompt


@pytest.mark.anyio
async def test_tty_approver_without_a_terminal_raises(tmp_path):
    # The proxy turns this exception into a rejection; see test_proxy.py.
    request = ApprovalRequest("id", "t", {}, "r")
    with pytest.raises(OSError):
        await tty_approver(str(tmp_path / "no-such-tty"))(request)


@pytest.mark.anyio
@pytest.mark.parametrize(("typed", "expected"), [(b"yes\n", True), (b"y\n", False), (b"\n", False)])
async def test_tty_approver_on_a_real_pty(typed, expected):
    master, slave = pty.openpty()
    try:
        os.write(master, typed)
        request = ApprovalRequest("id", "refund", {"amount": 1}, "r")
        assert await tty_approver(os.ttyname(slave))(request) is expected
        assert b"refund" in os.read(master, 4096)
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.anyio
async def test_stdio_handshake_for_older_clients(tmp_path):
    audit = tmp_path / "audit.jsonl"
    async with Client(proxy_params(audit), mode="legacy") as client:
        ok = await client.call_tool("read_file", {"path": "/workspace/notes.txt"})
    assert "synthetic demo note" in ok.content[0].text


@pytest.mark.anyio
async def test_command_approver_uses_exit_status(tmp_path):
    request = ApprovalRequest("id", "t", {}, "r")
    assert await command_approver(str(write_script(tmp_path / "y", "exit 0")))(request) is True
    assert await command_approver(str(write_script(tmp_path / "n", "exit 7")))(request) is False
