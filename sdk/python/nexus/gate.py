"""Policy gate for Python agents.

A :class:`PolicyGate` asks a running ``nexus-cli`` (``dev``, ``run`` or ``mcp serve``) through its
control API when one is discoverable, so taint tracking, session grants, one_time rules,
human-in-the-loop approval and auditing all apply. Without a daemon it falls back to running
``nexus-cli policy test`` per call (stateless).
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, TypeVar, Union
from urllib.parse import urlunparse

from ._types import DaemonNotFoundError, Decision, DeniedError, NexusError
from .client import Client

__all__ = ["Decision", "DeniedError", "Gate", "PolicyGate", "ToolCall", "guard", "default_gate", "set_default_gate"]

MODES = ("auto", "daemon", "subprocess")

F = TypeVar("F", bound=Callable[..., Any])
ArgsFrom = Union[Callable[..., Mapping[str, Any]], Sequence[str], Mapping[str, str], None]


@dataclass
class ToolCall:
    """A single action an agent wants to take: a named tool (with arguments) or an HTTP request."""

    method: str = "GET"
    host: str = ""
    path: str = ""
    tool: str = ""
    scopes: List[str] = field(default_factory=list)
    args: Optional[Dict[str, Any]] = None
    session: str = ""

    @property
    def url(self) -> str:
        if not self.host:
            return ""
        return urlunparse(("http", self.host, self.path or "/", "", "", ""))


class Gate(Protocol):
    """Authorizes tool calls; a non-allowed decision must abort the call."""

    def authorize(self, call: ToolCall) -> Decision: ...


class PolicyGate:
    """Gate backed by a running nexus-cli (daemon mode) or ``nexus-cli policy test`` (subprocess).

    :param binary: ``nexus-cli`` executable for subprocess mode.
    :param policy: policy file for subprocess mode. In daemon mode the daemon's own policy is used.
    :param mode: ``"auto"`` (default: the daemon when one is discoverable, else subprocess),
        ``"daemon"`` (raise :class:`~nexus.DaemonNotFoundError` if none) or ``"subprocess"``.
    :param client: an explicit :class:`~nexus.Client` (implies daemon mode unless ``mode`` says
        otherwise).

    In daemon mode a transport failure denies the call (fail closed). Subprocess mode is stateless:
    taint tracking, one_time rules and approvals only apply in daemon mode, and tool ``args``
    are not evaluated.
    """

    def __init__(
        self,
        binary: str = "nexus-cli",
        policy: str = "nexus.yaml",
        *,
        mode: str = "auto",
        client: Optional[Client] = None,
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {', '.join(MODES)}")
        self._binary = shutil.which(binary) or binary
        self._policy = policy
        self._mode = mode
        self._client = client
        self._resolved: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        """The effective mode: ``daemon`` or ``subprocess`` (resolving ``auto`` on first use)."""
        with self._lock:
            if self._resolved is None:
                self._resolved = self._resolve()
            return self._resolved

    @property
    def client(self) -> Optional[Client]:
        """The daemon client in daemon mode, else None."""
        return self._client if self.mode == "daemon" else None

    def _resolve(self) -> str:
        if self._mode == "subprocess":
            return "subprocess"
        if self._client is not None:
            return "daemon"
        try:
            self._client = Client()
        except DaemonNotFoundError:
            if self._mode == "daemon":
                raise
            return "subprocess"
        return "daemon"

    def authorize(self, call: ToolCall) -> Decision:
        if self.mode == "daemon":
            return self._authorize_daemon(call)
        return self._authorize_subprocess(call)

    async def authorize_async(self, call: ToolCall) -> Decision:
        """Async variant of :meth:`authorize` (runs in a worker thread)."""
        return await asyncio.to_thread(self.authorize, call)

    def _authorize_daemon(self, call: ToolCall) -> Decision:
        assert self._client is not None
        try:
            return self._client.check(
                call.tool,
                call.args,
                method=call.method if (call.host or not call.tool) else "",
                host=call.host,
                path=call.path,
                scopes=call.scopes,
                session=call.session or None,
            )
        except NexusError as exc:
            # Fail closed: an unreachable or erroring daemon denies the call.
            return Decision(allowed=False, reason=str(exc), source="guard")

    def _authorize_subprocess(self, call: ToolCall) -> Decision:
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
            out = subprocess.run(args, capture_output=True, text=True, check=True)
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


_default: Optional[Gate] = None
_default_lock = threading.Lock()


def default_gate() -> Gate:
    """The gate used by :func:`guard` when none is given: a shared ``PolicyGate(mode="auto")``."""
    global _default
    with _default_lock:
        if _default is None:
            _default = PolicyGate()
        return _default


def set_default_gate(gate: Optional[Gate]) -> None:
    """Replace (or with None, reset) the gate used by :func:`guard` when none is given."""
    global _default
    with _default_lock:
        _default = gate


def _extract_args(sig: inspect.Signature, args_from: ArgsFrom, a: tuple, kw: dict) -> Dict[str, Any]:
    bound = sig.bind_partial(*a, **kw)
    bound.apply_defaults()
    params = dict(bound.arguments)
    # Flatten **kwargs into the top level, as a tool's JSON arguments would be.
    for name, p in sig.parameters.items():
        if p.kind is inspect.Parameter.VAR_KEYWORD and name in params:
            extra = params.pop(name)
            for k, v in extra.items():
                params.setdefault(k, v)
    if args_from is None:
        params.pop("self", None)
        params.pop("cls", None)
        return params
    if callable(args_from):
        return dict(args_from(*a, **kw))
    if isinstance(args_from, Mapping):
        return {policy_name: params.get(param) for policy_name, param in args_from.items() if param in params}
    if isinstance(args_from, str):
        args_from = [args_from]
    return {name: params[name] for name in args_from if name in params}


def guard(
    gate: Optional[Gate] = None,
    *,
    tool: Optional[str] = None,
    method: str = "POST",
    scopes: Optional[Sequence[str]] = None,
    args_from: ArgsFrom = None,
) -> Callable[[F], F]:
    """Decorator that authorizes a (sync or async) tool function before it runs.

    The function's arguments become the policy ``args`` (for rules with ``args:`` matchers):
    by default all bound arguments (``self``/``cls`` dropped, ``**kwargs`` flattened). Narrow them
    with ``args_from``: a list of parameter names, a mapping ``{policy_arg: parameter}``, or a
    callable taking the same arguments as the function and returning a dict.

    Example::

        @guard(tool="fs__write", args_from=["path"])
        def write_file(path: str, content: str) -> None:
            ...

        @guard(gate, tool="shell__exec", args_from=lambda cmd, **_: {"cmd": cmd})
        async def run(cmd: str) -> str:
            ...

    Without ``gate`` the shared :func:`default_gate` is used (daemon when discoverable, else
    subprocess). A denial raises :class:`DeniedError` and the function is not called.
    """

    def decorator(fn: F) -> F:
        name = tool or fn.__name__
        sig = inspect.signature(fn)

        def make_call(a: tuple, kw: dict) -> ToolCall:
            return ToolCall(
                method=method,
                tool=name,
                scopes=list(scopes or []),
                args=_extract_args(sig, args_from, a, kw),
            )

        def check(decision: Decision) -> None:
            if not decision.allowed:
                raise DeniedError(f"nexus denied {name}: {decision.reason}", decision)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*a: Any, **kw: Any) -> Any:
                g = gate or default_gate()
                call = make_call(a, kw)
                auth = getattr(g, "authorize_async", None)
                if auth is not None:
                    decision = await auth(call)
                else:
                    decision = await asyncio.to_thread(g.authorize, call)
                check(decision)
                return await fn(*a, **kw)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*a: Any, **kw: Any) -> Any:
            g = gate or default_gate()
            check(g.authorize(make_call(a, kw)))
            return fn(*a, **kw)

        return wrapper  # type: ignore[return-value]

    return decorator
