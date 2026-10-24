"""Native client for a running nexus-cli's control API (``POST /v1/check`` and friends).

Stdlib only (``urllib``). The control API listens on loopback and is protected by a per-process
bearer token, discovered from ``NEXUS_CONTROL_URL``/``NEXUS_CONTROL_TOKEN`` or the discovery files
in ``$NEXUS_HOME/control``.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import quote, urlencode, urlparse

from ._discovery import ENV_PROXY_URL, ENV_TOKEN, ControlInfo, discover
from ._types import ApiError, DeniedError, Decision, NexusError, UnauthorizedError

Wait = Union[None, str, float, int]

DEFAULT_TIMEOUT = 600.0
"""Default socket timeout (seconds). Checks that go to a human block until they decide."""

_MAX_RESPONSE = 8 << 20
_DECISIONS = ("once", "session", "always", "deny")


@dataclass
class ApprovalRequest:
    """A pending human-in-the-loop approval, as listed by ``GET /v1/approvals``."""

    id: str
    agent_id: str = ""
    act_as: str = ""
    tool: str = ""
    target: str = ""
    params: str = ""
    reason: str = ""
    created: str = ""

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ApprovalRequest":
        return cls(**{k: str(d.get(k, "") or "") for k in cls.__dataclass_fields__})


@dataclass
class Status:
    """``GET /v1/status``: the endpoint's discovery info (without its token) plus queue length."""

    pid: int = 0
    addr: str = ""
    kind: str = ""
    started: str = ""
    listen: str = ""
    policy: str = ""
    cwd: str = ""
    pending: int = 0
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Status":
        return cls(
            pid=int(d.get("pid", 0) or 0),
            addr=str(d.get("addr", "")),
            kind=str(d.get("kind", "")),
            started=str(d.get("started", "")),
            listen=str(d.get("listen", "")),
            policy=str(d.get("policy", "")),
            cwd=str(d.get("cwd", "")),
            pending=int(d.get("pending", 0) or 0),
            raw=dict(d),
        )


def env_token() -> str:
    """The nexus JWT to send with checks: ``NEXUS_TOKEN``, else the password in ``NEXUS_PROXY_URL``."""
    tok = os.environ.get(ENV_TOKEN, "").strip()
    if tok:
        return tok
    raw = os.environ.get(ENV_PROXY_URL, "")
    if raw:
        try:
            return urlparse(raw).password or ""
        except ValueError:
            return ""
    return ""


def _wait_str(wait: Wait) -> Optional[str]:
    if wait is None:
        return None
    if isinstance(wait, bool):
        raise TypeError("wait must be a duration string or a number of seconds")
    if isinstance(wait, (int, float)):
        if wait < 0:
            raise ValueError("wait must not be negative")
        return "0" if wait == 0 else f"{float(wait):g}s"
    return str(wait)


class Client:
    """Synchronous client for a running ``nexus-cli dev``/``run``/``mcp serve``.

    Every check runs through the same policy engine, taint tracking, session grants, one_time
    rules, human-in-the-loop broker and audit log as that process's proxy/MCP traffic.

    Example::

        nx = nexus.Client()                       # discover the daemon
        d = nx.check(tool="fs__write", args={"path": "/etc/passwd"})
        if not d.allowed:
            print("denied:", d.reason)
        nx.require(tool="shell__exec", args={"cmd": "ls"})  # raises DeniedError

    :param url: control API base URL (``http://127.0.0.1:PORT``); discovered when omitted.
    :param control_token: bearer token for ``url`` (required with ``url``).
    :param token: nexus JWT sent with each check (default ``NEXUS_TOKEN`` or the password of
        ``NEXUS_PROXY_URL``). When present it is authoritative for agent identity and scopes.
    :param kind: only discover endpoints of this kind (``dev``, ``run``, ``mcp``).
    :param pid: only discover the endpoint of this process.
    :param agent_id: default agent id for checks; ``act_as`` and ``session`` likewise.
    :param timeout: socket timeout in seconds; keep it above the daemon's approval timeout.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        control_token: Optional[str] = None,
        *,
        token: Optional[str] = None,
        kind: Optional[str] = None,
        pid: Optional[int] = None,
        info: Optional[ControlInfo] = None,
        agent_id: str = "",
        act_as: str = "",
        session: str = "",
        timeout: Optional[float] = DEFAULT_TIMEOUT,
    ) -> None:
        if info is None:
            if url:
                if not control_token:
                    raise NexusError("control_token is required with url")
                u = urlparse(url)
                if u.scheme != "http" or not u.netloc:
                    raise NexusError(f"invalid control url {url!r} (want http://host:port)")
                info = ControlInfo(addr=u.netloc, token=control_token)
            else:
                info = discover(kind=kind, pid=pid)
        self.info = info
        self.token = env_token() if token is None else token
        self.agent_id = agent_id
        self.act_as = act_as
        self.session = session
        self.timeout = timeout
        # Never route loopback control traffic through HTTP(S)_PROXY (which may be nexus itself).
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @property
    def url(self) -> str:
        """Base URL of the control API."""
        return self.info.url

    def _request(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None) -> "tuple[int, Any]":
        data = None
        headers = {"Authorization": f"Bearer {self.info.token}", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, default=str).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            resp = self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as err:
            status, payload = err.code, err.read(_MAX_RESPONSE)
            err.close()
        except urllib.error.URLError as err:
            raise NexusError(f"nexus control API {self.url}: {err.reason}") from err
        else:
            with resp:
                status, payload = resp.status, resp.read(_MAX_RESPONSE)
        parsed: Any = None
        if payload:
            try:
                parsed = json.loads(payload)
            except ValueError:
                parsed = None
        if status >= 400:
            msg = parsed.get("error") if isinstance(parsed, dict) else None
            msg = msg or (payload or b"").decode("utf-8", "replace").strip() or "request failed"
            if status == 401:
                raise UnauthorizedError(status, msg)
            raise ApiError(status, msg)
        return status, parsed

    def build_request(
        self,
        tool: str = "",
        args: Optional[Mapping[str, Any]] = None,
        *,
        method: str = "",
        host: str = "",
        path: str = "",
        provider: str = "",
        scopes: Optional[Sequence[str]] = None,
        agent_id: Optional[str] = None,
        act_as: Optional[str] = None,
        session: Optional[str] = None,
        token: Optional[str] = None,
        wait: Wait = None,
    ) -> Dict[str, Any]:
        """The JSON body :meth:`check` sends (empty fields omitted)."""
        body: Dict[str, Any] = {
            "agent_id": self.agent_id if agent_id is None else agent_id,
            "act_as": self.act_as if act_as is None else act_as,
            "session": self.session if session is None else session,
            "token": self.token if token is None else token,
            "tool": tool,
            "provider": provider,
            "method": method,
            "host": host,
            "path": path,
            "wait": _wait_str(wait) or "",
        }
        body = {k: v for k, v in body.items() if v}
        if scopes:
            body["scopes"] = list(scopes)
        if args is not None:
            body["args"] = dict(args)
        return body

    def check(
        self,
        tool: str = "",
        args: Optional[Mapping[str, Any]] = None,
        *,
        method: str = "",
        host: str = "",
        path: str = "",
        provider: str = "",
        scopes: Optional[Sequence[str]] = None,
        agent_id: Optional[str] = None,
        act_as: Optional[str] = None,
        session: Optional[str] = None,
        token: Optional[str] = None,
        wait: Wait = None,
    ) -> Decision:
        """Authorize a tool call (``tool`` + ``args``) or an HTTP request (``method``/``host``/``path``).

        With ``wait=None`` a call that needs human approval blocks until it is decided or the
        daemon's approval timeout expires. With ``wait=0`` (or a duration such as ``"5s"`` or
        ``5``) an undecided call returns ``Decision(decision="pending", approval_id=...)``;
        resolve it with :meth:`poll`.
        """
        body = self.build_request(
            tool, args, method=method, host=host, path=path, provider=provider, scopes=scopes,
            agent_id=agent_id, act_as=act_as, session=session, token=token, wait=wait,
        )
        _, resp = self._request("POST", "/v1/check", body)
        return Decision.from_response(resp or {})

    def poll(self, approval_id: str, wait: Wait = None) -> Decision:
        """Result of a pending check; with ``wait`` it long-polls up to that long (max 60s)."""
        if not approval_id or any(c in approval_id for c in "/?#"):
            raise NexusError(f"invalid approval id {approval_id!r}")
        path = "/v1/check/" + quote(approval_id, safe="")
        w = _wait_str(wait)
        if w:
            path += "?" + urlencode({"wait": w})
        _, resp = self._request("GET", path)
        return Decision.from_response(resp or {})

    def require(self, tool: str = "", args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Decision:
        """Like :meth:`check` but raises :class:`DeniedError` unless the call is allowed."""
        d = self.check(tool, args, **kwargs)
        if not d.allowed:
            what = tool or " ".join(x for x in (kwargs.get("method", ""), kwargs.get("host", "") + kwargs.get("path", "")) if x)
            if d.pending:
                raise DeniedError(f"nexus: {what} is pending approval {d.approval_id}", d)
            raise DeniedError(f"nexus denied {what}: {d.reason}", d)
        return d

    def approvals(self) -> List[ApprovalRequest]:
        """Pending human-in-the-loop approvals, oldest first."""
        _, resp = self._request("GET", "/v1/approvals")
        return [ApprovalRequest.from_dict(r) for r in (resp or [])]

    def decide(self, approval_id: str, decision: str) -> None:
        """Decide a pending approval: ``once``, ``session``, ``always`` or ``deny``."""
        if decision not in _DECISIONS:
            raise ValueError(f"decision must be one of {', '.join(_DECISIONS)}")
        if not approval_id or any(c in approval_id for c in "/?#"):
            raise NexusError(f"invalid approval id {approval_id!r}")
        self._request("POST", "/v1/approvals/" + quote(approval_id, safe=""), {"decision": decision})

    def status(self) -> Status:
        """The endpoint's status (kind, pid, proxy listen address, pending approvals)."""
        _, resp = self._request("GET", "/v1/status")
        return Status.from_dict(resp or {})


class AsyncClient:
    """``asyncio`` wrapper around :class:`Client`; each call runs in a worker thread.

    Accepts the same arguments as :class:`Client` (or an existing one via ``client=``).
    """

    def __init__(self, *args: Any, client: Optional[Client] = None, **kwargs: Any) -> None:
        self._client = client or Client(*args, **kwargs)

    @property
    def sync(self) -> Client:
        """The underlying synchronous client."""
        return self._client

    @property
    def info(self) -> ControlInfo:
        return self._client.info

    async def check(self, tool: str = "", args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Decision:
        """See :meth:`Client.check`."""
        return await asyncio.to_thread(self._client.check, tool, args, **kwargs)

    async def require(self, tool: str = "", args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Decision:
        """See :meth:`Client.require`."""
        return await asyncio.to_thread(self._client.require, tool, args, **kwargs)

    async def poll(self, approval_id: str, wait: Wait = None) -> Decision:
        """See :meth:`Client.poll`."""
        return await asyncio.to_thread(self._client.poll, approval_id, wait)

    async def approvals(self) -> List[ApprovalRequest]:
        """See :meth:`Client.approvals`."""
        return await asyncio.to_thread(self._client.approvals)

    async def decide(self, approval_id: str, decision: str) -> None:
        """See :meth:`Client.decide`."""
        await asyncio.to_thread(self._client.decide, approval_id, decision)

    async def status(self) -> Status:
        """See :meth:`Client.status`."""
        return await asyncio.to_thread(self._client.status)
