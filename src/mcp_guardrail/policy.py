"""The policy file and the decision function.

Nothing here imports MCP, so every decision can be tested as a pure function.
Parsing is strict on purpose: a misspelled key such as ``aproval: true`` would
otherwise silently remove a control, so unknown keys are a load error.
"""

from __future__ import annotations

import math
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import yaml

REDACTED = "[redacted]"


class PolicyError(ValueError):
    """The policy file is invalid. The proxy refuses to start."""


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str


def _normalize_path(value: str) -> str:
    normalized = posixpath.normpath(value)
    # POSIX lets normpath keep exactly two leading slashes; treat them as one.
    return "/" + normalized.lstrip("/") if normalized.startswith("//") else normalized


def _under_prefix(path: str, prefix: str) -> bool:
    normalized = _normalize_path(path)
    return normalized == prefix or normalized.startswith(prefix.rstrip("/") + "/")


@dataclass(frozen=True)
class ArgRule:
    """Constraints on one argument. Declaring a rule with no constraints permits any value."""

    path_prefix: tuple[str, ...] = ()
    max: float | None = None
    min: float | None = None
    one_of: tuple[Any, ...] | None = None
    pattern: re.Pattern[str] | None = None
    max_length: int | None = None
    optional: bool = False
    redact: bool = False

    def violation(self, value: Any) -> str | None:
        """Return why ``value`` breaks this rule, or None when it passes."""
        if self.path_prefix:
            problem = self._path_violation(value)
            if problem:
                return problem
        if self.max is not None or self.min is not None:
            # bool is an int subclass and NaN compares false with everything.
            if isinstance(value, bool) or not isinstance(value, int | float):
                return "must be a number"
            if not math.isfinite(value):
                return "must be finite"
            if self.max is not None and value > self.max:
                return f"{value} is above the maximum of {self.max}"
            if self.min is not None and value < self.min:
                return f"{value} is below the minimum of {self.min}"
        # Compare types too: in Python True == 1, which JSON does not mean.
        if self.one_of is not None and not any(
            type(value) is type(option) and value == option for option in self.one_of
        ):
            return f"must be one of {list(self.one_of)}"
        if self.pattern is not None and not (
            isinstance(value, str) and self.pattern.fullmatch(value)
        ):
            return f"must fully match {self.pattern.pattern!r}"
        if self.max_length is not None and (
            not isinstance(value, str) or len(value) > self.max_length
        ):
            return f"must be a string of at most {self.max_length} characters"
        return None

    def _path_violation(self, value: Any) -> str | None:
        if not isinstance(value, str):
            return "must be a string path"
        if "\\" in value or any(ord(c) < 32 for c in value):
            return "contains a backslash or control character"
        # Check the decoded form too, in case the server percent-decodes.
        for candidate in {value, unquote(value)}:
            if not any(_under_prefix(candidate, prefix) for prefix in self.path_prefix):
                return f"resolves outside {list(self.path_prefix)}"
        return None


@dataclass(frozen=True)
class ToolPolicy:
    read_only: bool = False
    approval: bool = False
    allow_other_args: bool = False
    args: Mapping[str, ArgRule] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    tools: Mapping[str, ToolPolicy]
    read_only_mode: bool = False
    approval_timeout_seconds: float = 120.0

    def exposes(self, tool: str) -> bool:
        """Whether a tool appears in tools/list. Hidden tools are also denied on call."""
        rule = self.tools.get(tool)
        return rule is not None and (rule.read_only or not self.read_only_mode)

    def decide(self, tool: str, arguments: Mapping[str, Any] | None) -> Decision:
        """Decide one call. Argument rules run first, so a human never sees a doomed request."""
        rule = self.tools.get(tool)
        if rule is None:
            return Decision(Verdict.DENY, f"tool '{tool}' is not in the policy")
        if self.read_only_mode and not rule.read_only:
            return Decision(Verdict.DENY, f"read_only_mode is on and '{tool}' is not read-only")

        args = arguments or {}
        for name, arg_rule in rule.args.items():
            if name not in args:
                if arg_rule.optional:
                    continue
                # A missing argument may take a server-side default the rule never saw.
                return Decision(Verdict.DENY, f"argument '{name}' is required by policy")
            problem = arg_rule.violation(args[name])
            if problem:
                return Decision(Verdict.DENY, f"argument '{name}' {problem}")
        if not rule.allow_other_args:
            undeclared = sorted(set(args) - set(rule.args))
            if undeclared:
                return Decision(Verdict.DENY, f"undeclared arguments: {undeclared}")

        if rule.approval:
            return Decision(Verdict.NEEDS_APPROVAL, f"policy requires approval for '{tool}'")
        return Decision(Verdict.ALLOW, "policy allows this call")

    def redacted(self, tool: str, arguments: Mapping[str, Any] | None) -> dict[str, Any]:
        """The arguments as they may be written to the audit log."""
        rule = self.tools.get(tool)
        fields = rule.args if rule else {}
        return {
            name: REDACTED if name in fields and fields[name].redact else value
            for name, value in (arguments or {}).items()
        }


def _expect_mapping(where: str, raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping")
    return raw


def _expect_keys(where: str, raw: Any, allowed: set[str]) -> dict[str, Any]:
    raw = _expect_mapping(where, raw)
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyError(f"{where}: unknown keys {unknown}; allowed: {sorted(allowed)}")
    return raw


def _expect_bool(where: str, raw: dict[str, Any], key: str) -> bool:
    value = raw.get(key, False)
    if not isinstance(value, bool):
        raise PolicyError(f"{where}.{key}: expected true or false")
    return value


def _number(where: str, value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyError(f"{where}: expected a number")
    return value


def _parse_arg(where: str, raw: Any) -> ArgRule:
    allowed = {"path_prefix", "max", "min", "one_of", "pattern", "max_length", "optional", "redact"}
    data = _expect_keys(where, raw, allowed)

    prefixes = data.get("path_prefix", [])
    prefixes = [prefixes] if isinstance(prefixes, str) else prefixes
    if not isinstance(prefixes, list) or not all(
        isinstance(p, str) and p.startswith("/") for p in prefixes
    ):
        raise PolicyError(f"{where}.path_prefix: expected absolute paths")

    one_of = data.get("one_of")
    if one_of is not None and not isinstance(one_of, list):
        raise PolicyError(f"{where}.one_of: expected a list")

    pattern = data.get("pattern")
    try:
        compiled = re.compile(pattern) if pattern is not None else None
    except (re.error, TypeError) as exc:
        raise PolicyError(f"{where}.pattern: {exc}") from exc

    max_length = data.get("max_length")
    if max_length is not None and (isinstance(max_length, bool) or not isinstance(max_length, int)):
        raise PolicyError(f"{where}.max_length: expected an integer")

    return ArgRule(
        path_prefix=tuple(_normalize_path(p) for p in prefixes),
        max=_number(f"{where}.max", data.get("max")),
        min=_number(f"{where}.min", data.get("min")),
        one_of=tuple(one_of) if one_of is not None else None,
        pattern=compiled,
        max_length=max_length,
        optional=_expect_bool(where, data, "optional"),
        redact=_expect_bool(where, data, "redact"),
    )


def _parse_tool(where: str, raw: Any) -> ToolPolicy:
    data = _expect_keys(where, raw, {"read_only", "approval", "allow_other_args", "args"})
    args = _expect_mapping(f"{where}.args", data.get("args"))
    return ToolPolicy(
        read_only=_expect_bool(where, data, "read_only"),
        approval=_expect_bool(where, data, "approval"),
        allow_other_args=_expect_bool(where, data, "allow_other_args"),
        args={name: _parse_arg(f"{where}.args.{name}", rule) for name, rule in args.items()},
    )


def parse_policy(raw: Any) -> Policy:
    data = _expect_keys(
        "policy", raw, {"version", "read_only_mode", "approval_timeout_seconds", "tools"}
    )
    if data.get("version") != 1:
        raise PolicyError("policy.version: expected 1")
    timeout = _number("policy.approval_timeout_seconds", data.get("approval_timeout_seconds", 120))
    if timeout is None or timeout <= 0:
        raise PolicyError("policy.approval_timeout_seconds: expected a positive number")
    tools = _expect_mapping("policy.tools", data.get("tools"))
    return Policy(
        tools={name: _parse_tool(f"tools.{name}", rule) for name, rule in tools.items()},
        read_only_mode=_expect_bool("policy", data, "read_only_mode"),
        approval_timeout_seconds=float(timeout),
    )


def load_policy(path: str | Path) -> Policy:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: {exc}") from exc
    return parse_policy(raw)
