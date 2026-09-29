"""Nexus SDK: gate agent tool calls through nexus-cli's least-privilege policy.

This lets Python agent frameworks (LangChain, OpenAI Agents, JarvisCore Agents, pydantic-ai, custom loops)
authorize every tool call against the same ``nexus.yaml`` policy the proxy and MCP gateway use,
without embedding the policy engine. Decisions are delegated to the ``nexus-cli`` binary.
"""

from .gate import (
    Decision,
    DeniedError,
    Gate,
    PolicyGate,
    ToolCall,
    guard,
)

__all__ = [
    "Decision",
    "DeniedError",
    "Gate",
    "PolicyGate",
    "ToolCall",
    "guard",
]

__version__ = "0.1.0"
