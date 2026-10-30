"""Command line: run the proxy, explain a decision, check a policy against a server."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

import anyio
from mcp import Client, StdioServerParameters
from mcp.server.stdio import stdio_server

from mcp_guardrail.approval import approver_from_spec
from mcp_guardrail.audit import AuditLog
from mcp_guardrail.policy import Policy, PolicyError, Verdict, load_policy
from mcp_guardrail.proxy import GuardrailProxy, list_all_tools, read_only_conflict

EXIT_CODES = {Verdict.ALLOW: 0, Verdict.DENY: 1, Verdict.NEEDS_APPROVAL: 2}


def _upstream(command: Sequence[str], pass_env: Sequence[str]) -> StdioServerParameters:
    if not command:
        raise SystemExit("error: give the upstream server command after --")
    # The SDK gives a child a minimal environment by default. Keep that and add
    # only what was asked for, so the proxy does not leak its environment upstream.
    env = {name: os.environ[name] for name in pass_env if name in os.environ}
    return StdioServerParameters(command=command[0], args=list(command[1:]), env=env or None)


async def _run(args: argparse.Namespace, policy: Policy) -> None:
    audit = AuditLog(args.audit)
    try:
        approver = approver_from_spec(args.approver)
        async with Client(_upstream(args.command, args.pass_env)) as upstream:
            server = GuardrailProxy(policy, upstream, audit, approver).server()
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
    finally:
        audit.close()


def _describe(policy: Policy, tool: str) -> str:
    rule = policy.tools.get(tool)
    if not policy.exposes(tool) or rule is None:
        return "hidden"
    labels = ["read-only" if rule.read_only else "write"]
    if rule.approval:
        labels.append("approval")
    if rule.args:
        labels.append(f"{len(rule.args)} arg rule(s)")
    return ", ".join(labels)


async def _check(args: argparse.Namespace, policy: Policy) -> int:
    problems = 0
    async with Client(_upstream(args.command, args.pass_env)) as upstream:
        tools = await list_all_tools(upstream)
    names = {tool.name for tool in tools}
    for tool in sorted(tools, key=lambda t: t.name):
        rule = policy.tools.get(tool.name)
        conflict = read_only_conflict(tool) if rule and rule.read_only else None
        if conflict:
            problems += 1
            print(f"{tool.name:24} CONFLICT: policy says read-only but {conflict}")
        else:
            print(f"{tool.name:24} {_describe(policy, tool.name)}")
    for missing in sorted(set(policy.tools) - names):
        problems += 1
        print(f"{missing:24} MISSING: in the policy but not on the server")
    return 1 if problems else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-guardrail", description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    run = sub.add_parser("run", help="proxy an upstream stdio server over stdio")
    run.add_argument("--policy", required=True)
    run.add_argument("--audit", required=True, help="JSONL audit log, appended to")
    run.add_argument("--approver", default="deny", help="deny (default), tty or cmd:<command>")
    run.add_argument("--pass-env", action="append", default=[], metavar="NAME")
    run.add_argument("command", nargs="*", help="upstream command, after --")

    explain = sub.add_parser("explain", help="print the decision for one call; no server needed")
    explain.add_argument("--policy", required=True)
    explain.add_argument("tool")
    explain.add_argument("arguments", nargs="?", default="{}", help="JSON object")

    check = sub.add_parser("check", help="compare a policy with what a server actually offers")
    check.add_argument("--policy", required=True)
    check.add_argument("--pass-env", action="append", default=[], metavar="NAME")
    check.add_argument("command", nargs="*", help="upstream command, after --")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if args.action == "explain":
        try:
            call_args: Any = json.loads(args.arguments)
        except json.JSONDecodeError as exc:
            print(f"error: arguments are not valid JSON: {exc}", file=sys.stderr)
            return 3
        if not isinstance(call_args, dict):
            print("error: arguments must be a JSON object", file=sys.stderr)
            return 3
        decision = policy.decide(args.tool, call_args)
        print(f"{decision.verdict.value}: {decision.reason}")
        return EXIT_CODES[decision.verdict]
    if args.action == "check":
        return anyio.run(_check, args, policy)
    if args.action == "run":
        approver_from_spec(args.approver)  # Fail before spawning anything.
        anyio.run(_run, args, policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
