"""mcp-guardrail: a policy proxy for MCP tool calls."""

from mcp_guardrail.policy import Decision, Policy, PolicyError, Verdict, load_policy

__all__ = ["Decision", "Policy", "PolicyError", "Verdict", "load_policy"]
__version__ = "0.1.0"
