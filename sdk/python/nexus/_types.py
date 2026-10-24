"""Shared result and error types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Decision:
    """The outcome of authorizing a tool call.

    ``allowed`` is the only field a caller must act on. ``decision`` is ``"allow"``, ``"deny"`` or
    (for non-blocking daemon checks) ``"pending"``; ``source`` says who decided (``policy``,
    ``approve``, ``default`` or ``guard``) and ``approval_id`` identifies the human approval request
    when the call went to one.
    """

    allowed: bool
    reason: str = ""
    decision: str = ""
    rule: str = ""
    source: str = ""
    approval_id: str = ""

    def __post_init__(self) -> None:
        if not self.decision:
            self.decision = "allow" if self.allowed else "deny"

    @property
    def pending(self) -> bool:
        """True when a human has not decided yet (only with ``wait=``); poll with ``approval_id``."""
        return self.decision == "pending"

    @classmethod
    def from_response(cls, body: dict) -> "Decision":
        """Build a Decision from a ``/v1/check`` JSON response."""
        decision = str(body.get("decision", "deny"))
        return cls(
            allowed=decision == "allow",
            reason=str(body.get("reason", "")),
            decision=decision,
            rule=str(body.get("rule", "")),
            source=str(body.get("source", "")),
            approval_id=str(body.get("approval_id", "")),
        )


class NexusError(Exception):
    """Base class for SDK errors."""


class DeniedError(NexusError):
    """Raised when a tool call is denied by policy or human-in-the-loop (or is still pending)."""

    def __init__(self, message: str, decision: Optional[Decision] = None) -> None:
        super().__init__(message)
        self.decision = decision


class DaemonNotFoundError(NexusError):
    """No running ``nexus-cli`` (dev, run or mcp serve) control endpoint could be found."""


class ApiError(NexusError):
    """The control API rejected a request."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"nexus control API: {message} (HTTP {status})")
        self.status = status
        self.message = message


class UnauthorizedError(ApiError):
    """The control token was rejected (e.g. a stale discovery file whose port was reused)."""
