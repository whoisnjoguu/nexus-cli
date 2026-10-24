"""Nexus SDK: gate agent tool calls through nexus-cli's least-privilege policy.

This lets Python agent frameworks (LangChain, OpenAI Agents, JarvisCore Agents, pydantic-ai, custom loops)
authorize every tool call against the same ``nexus.yaml`` policy the proxy and MCP gateway use.

* :class:`Client` / :class:`AsyncClient` talk to a running ``nexus-cli dev``/``run``/``mcp serve``
  over its loopback control API (``POST /v1/check``), so taint tracking, session grants, one_time
  rules, human-in-the-loop approval and auditing all apply.
* :func:`guard` and :class:`PolicyGate` use that daemon when one is discoverable and fall back to
  ``nexus-cli policy test`` otherwise.
* :func:`requests_session` / :func:`httpx_client` route HTTP through the nexus proxy.

The core is standard-library only; ``httpx`` and ``requests`` are optional extras.
"""

from ._discovery import ControlInfo, discover, list_endpoints
from ._types import (
    ApiError,
    DaemonNotFoundError,
    Decision,
    DeniedError,
    NexusError,
    UnauthorizedError,
)
from .client import ApprovalRequest, AsyncClient, Client, Status
from .gate import Gate, PolicyGate, ToolCall, default_gate, guard, set_default_gate
from .http import async_httpx_client, ca_bundle, httpx_client, proxy_url, requests_session

__all__ = [
    "ApiError",
    "ApprovalRequest",
    "AsyncClient",
    "Client",
    "ControlInfo",
    "DaemonNotFoundError",
    "Decision",
    "DeniedError",
    "Gate",
    "NexusError",
    "PolicyGate",
    "Status",
    "ToolCall",
    "UnauthorizedError",
    "async_httpx_client",
    "ca_bundle",
    "default_gate",
    "discover",
    "guard",
    "httpx_client",
    "list_endpoints",
    "proxy_url",
    "requests_session",
    "set_default_gate",
]

__version__ = "0.2.0"
