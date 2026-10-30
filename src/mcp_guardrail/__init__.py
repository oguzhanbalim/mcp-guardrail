"""mcp-guardrail: a policy proxy for MCP tool calls."""

from mcp_guardrail.audit import AuditLog
from mcp_guardrail.policy import Decision, Policy, PolicyError, Verdict, load_policy
from mcp_guardrail.proxy import GuardrailProxy

__all__ = [
    "AuditLog",
    "Decision",
    "GuardrailProxy",
    "Policy",
    "PolicyError",
    "Verdict",
    "load_policy",
]
__version__ = "0.1.0"
