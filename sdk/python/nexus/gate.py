"""Policy gate for Python agents, delegating decisions to the nexus-cli binary."""

from __future__ import annotations

import functools
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol
from urllib.parse import urlunparse


class DeniedError(Exception):
    """Raised when a tool call is denied by policy or human-in-the-loop."""


@dataclass
class ToolCall:
    """A single action an agent wants to take."""

    method: str = "GET"
    host: str = ""
    path: str = ""
    tool: str = ""
    scopes: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        if not self.host:
            return ""
        return urlunparse(("http", self.host, self.path or "/", "", "", ""))


@dataclass
class Decision:
    """The outcome of authorizing a tool call."""

    allowed: bool
    reason: str


class Gate(Protocol):
    """Authorizes tool calls; a non-allowed decision must abort the call."""

    def authorize(self, call: ToolCall) -> Decision: ...


class PolicyGate:
    """Gate backed by ``nexus-cli policy test``.

    Because the CLI owns the policy engine, decisions here match the proxy and MCP gateway
    exactly. Note: ``policy test`` is stateless, so cross-call taint tracking is only enforced
    by the long-running proxy/gateway, not this per-call check.
    """

    def __init__(self, binary: str = "nexus-cli", policy: str = "nexus.yaml") -> None:
        resolved = shutil.which(binary) or binary
        self._binary = resolved
        self._policy = policy

    def authorize(self, call: ToolCall) -> Decision:
        args = [
            self._binary,
            "policy",
            "test",
            "--policy",
            self._policy,
            "--method",
            call.method,
        ]
        if call.url:
            args += ["--url", call.url]
        if call.tool:
            args += ["--tool", call.tool]
        if call.scopes:
            args += ["--scopes", ",".join(call.scopes)]

        try:
            out = subprocess.run(args, capture_output=True,
                                 text=True, check=True)
        except FileNotFoundError as exc:
            raise DeniedError(f"nexus-cli not found: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            # Fail closed: a policy evaluation error denies the call.
            return Decision(allowed=False, reason=(exc.stderr or exc.stdout or "policy error").strip())

        decision, reason = "DENY", ""
        for line in out.stdout.splitlines():
            if line.startswith("Decision:"):
                decision = line.split(":", 1)[1].strip()
            elif line.startswith("Reason:"):
                reason = line.split(":", 1)[1].strip()
        return Decision(allowed=decision == "ALLOW", reason=reason)


def guard(
    gate: Gate,
    *,
    tool: Optional[str] = None,
    method: str = "POST",
    scopes: Optional[list[str]] = None,
) -> Callable:
    """Decorator that authorizes a tool function before it runs.

    Example::

        gate = PolicyGate()

        @guard(gate, tool="execute_shell")
        def execute_shell(cmd: str) -> str:
            ...
    """

    def decorator(fn: Callable) -> Callable:
        call = ToolCall(method=method, tool=tool or fn.__name__,
                        scopes=scopes or [])

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            decision = gate.authorize(call)
            if not decision.allowed:
                raise DeniedError(
                    f"nexus denied {call.tool}: {decision.reason}")
            return fn(*args, **kwargs)

        return wrapper

    return decorator
