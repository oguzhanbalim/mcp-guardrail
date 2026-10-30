from __future__ import annotations

import pytest

from mcp_guardrail.policy import PolicyError, Verdict, load_policy, parse_policy


def policy(tools, **top):
    return parse_policy({"version": 1, "tools": tools, **top})


def verdict(p, tool, args=None):
    return p.decide(tool, args).verdict


def test_unlisted_tool_is_denied_and_hidden():
    p = policy({"ping": {}})
    assert verdict(p, "ping") is Verdict.ALLOW
    assert verdict(p, "nope") is Verdict.DENY
    assert not p.exposes("nope")


def test_read_only_mode_blocks_writes_only():
    p = policy({"r": {"read_only": True}, "w": {}}, read_only_mode=True)
    assert verdict(p, "r") is Verdict.ALLOW
    assert verdict(p, "w") is Verdict.DENY
    assert p.exposes("r")
    assert not p.exposes("w")


def test_approval_is_only_asked_after_argument_rules_pass():
    p = policy({"pay": {"approval": True, "args": {"amount": {"max": 10}}}})
    assert verdict(p, "pay", {"amount": 5}) is Verdict.NEEDS_APPROVAL
    assert verdict(p, "pay", {"amount": 50}) is Verdict.DENY


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/workspace", Verdict.ALLOW),
        ("/workspace/a.txt", Verdict.ALLOW),
        ("/workspace/sub/../a.txt", Verdict.ALLOW),
        ("//workspace/a.txt", Verdict.ALLOW),
        ("/workspace/../etc/passwd", Verdict.DENY),
        ("/workspace-evil/a.txt", Verdict.DENY),
        ("/workspace/%2e%2e/etc/passwd", Verdict.DENY),
        ("/etc/passwd", Verdict.DENY),
        ("workspace/a.txt", Verdict.DENY),
        ("../workspace/a.txt", Verdict.DENY),
        ("/workspace\\..\\etc", Verdict.DENY),
        ("/workspace/a\x00.txt", Verdict.DENY),
        ("file:///workspace/a.txt", Verdict.DENY),
        (["/workspace/a.txt"], Verdict.DENY),
        (None, Verdict.DENY),
    ],
)
def test_path_prefix(path, expected):
    p = policy({"read": {"args": {"path": {"path_prefix": "/workspace"}}}})
    assert verdict(p, "read", {"path": path}) is expected


def test_root_prefix_allows_absolute_paths():
    p = policy({"read": {"args": {"path": {"path_prefix": "/"}}}})
    assert verdict(p, "read", {"path": "/etc/hosts"}) is Verdict.ALLOW
    assert verdict(p, "read", {"path": "etc/hosts"}) is Verdict.DENY


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (100, Verdict.ALLOW),
        (0.01, Verdict.ALLOW),
        (100.01, Verdict.DENY),
        (0, Verdict.DENY),
        ("50", Verdict.DENY),
        (True, Verdict.DENY),
        (float("nan"), Verdict.DENY),
        (float("inf"), Verdict.DENY),
        (None, Verdict.DENY),
    ],
)
def test_numeric_bounds(amount, expected):
    p = policy({"pay": {"args": {"amount": {"min": 0.01, "max": 100}}}})
    assert verdict(p, "pay", {"amount": amount}) is expected


def test_one_of_does_not_confuse_true_with_one():
    p = policy({"t": {"args": {"level": {"one_of": [1, 2]}}}})
    assert verdict(p, "t", {"level": 1}) is Verdict.ALLOW
    assert verdict(p, "t", {"level": True}) is Verdict.DENY
    assert verdict(p, "t", {"level": 3}) is Verdict.DENY


def test_pattern_must_match_whole_value():
    p = policy({"t": {"args": {"id": {"pattern": "ORD-[0-9]+"}}}})
    assert verdict(p, "t", {"id": "ORD-12"}) is Verdict.ALLOW
    assert verdict(p, "t", {"id": "ORD-12; DROP TABLE"}) is Verdict.DENY
    assert verdict(p, "t", {"id": 12}) is Verdict.DENY


def test_max_length():
    p = policy({"t": {"args": {"s": {"max_length": 3}}}})
    assert verdict(p, "t", {"s": "abc"}) is Verdict.ALLOW
    assert verdict(p, "t", {"s": "abcd"}) is Verdict.DENY


def test_missing_argument_is_denied_unless_optional():
    # A missing argument may take a server-side default that the rule never saw.
    p = policy({"t": {"args": {"path": {"path_prefix": "/w"}, "n": {"max": 1, "optional": True}}}})
    assert verdict(p, "t", {}) is Verdict.DENY
    assert verdict(p, "t", {"path": "/w/a"}) is Verdict.ALLOW


def test_undeclared_arguments_are_denied_by_default():
    p = policy({"strict": {"args": {"a": {}}}, "loose": {"allow_other_args": True}})
    assert verdict(p, "strict", {"a": 1, "force": True}) is Verdict.DENY
    assert verdict(p, "loose", {"force": True}) is Verdict.ALLOW


def test_redaction_only_touches_marked_arguments():
    p = policy({"t": {"args": {"secret": {"redact": True}, "plain": {}}}})
    assert p.redacted("t", {"secret": "s3", "plain": "ok"}) == {
        "secret": "[redacted]",
        "plain": "ok",
    }


@pytest.mark.parametrize(
    "raw",
    [
        {"tools": {}},
        {"version": 2, "tools": {}},
        {"version": 1, "toolz": {}},
        {"version": 1, "tools": {"t": {"aproval": True}}},
        {"version": 1, "tools": {"t": {"approval": "yes"}}},
        {"version": 1, "tools": {"t": {"args": {"a": {"maximum": 1}}}}},
        {"version": 1, "tools": {"t": {"args": {"a": {"max": "100"}}}}},
        {"version": 1, "tools": {"t": {"args": {"a": {"path_prefix": "relative/"}}}}},
        {"version": 1, "tools": {"t": {"args": {"a": {"pattern": "("}}}}},
        {"version": 1, "tools": {"t": {"args": 5}}},
        {"version": 1, "tools": [], "approval_timeout_seconds": 0},
        ["not", "a", "mapping"],
    ],
)
def test_invalid_policies_refuse_to_load(raw):
    with pytest.raises(PolicyError):
        parse_policy(raw)


def test_example_policy_loads():
    p = load_policy("examples/policy.yaml")
    assert set(p.tools) == {"read_file", "write_file", "issue_refund"}
