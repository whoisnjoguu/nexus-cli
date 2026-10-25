"""Discovery of running nexus-cli control endpoints."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from ._types import DaemonNotFoundError

ENV_CONTROL_URL = "NEXUS_CONTROL_URL"
ENV_CONTROL_TOKEN = "NEXUS_CONTROL_TOKEN"
ENV_TOKEN = "NEXUS_TOKEN"
ENV_PROXY_URL = "NEXUS_PROXY_URL"
ENV_HOME = "NEXUS_HOME"

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass
class ControlInfo:
    """A running control endpoint, as advertised in ``$NEXUS_HOME/control/<pid>.json``."""

    addr: str
    token: str
    pid: int = 0
    kind: str = ""
    started: str = ""
    listen: str = ""
    policy: str = ""
    cwd: str = ""

    @property
    def url(self) -> str:
        """Base URL of the control API, e.g. ``http://127.0.0.1:49152``."""
        return f"http://{self.addr}"

    @property
    def started_at(self) -> datetime:
        """``started`` parsed as an aware datetime (epoch if missing or unparsable)."""
        return _parse_time(self.started)

    @classmethod
    def from_dict(cls, d: dict) -> "ControlInfo":
        return cls(
            addr=str(d.get("addr", "")),
            token=str(d.get("token", "")),
            pid=int(d.get("pid", 0) or 0),
            kind=str(d.get("kind", "")),
            started=str(d.get("started", "")),
            listen=str(d.get("listen", "")),
            policy=str(d.get("policy", "")),
            cwd=str(d.get("cwd", "")),
        )


def _parse_time(s: str) -> datetime:
    if not s:
        return _EPOCH
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Go emits up to nanosecond precision; fromisoformat (3.9) accepts at most microseconds.
    if "." in s:
        head, _, rest = s.partition(".")
        frac = ""
        i = 0
        while i < len(rest) and rest[i].isdigit():
            frac += rest[i]
            i += 1
        s = f"{head}.{frac[:6].ljust(6, '0')}{rest[i:]}"
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return _EPOCH
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t


def control_dir() -> Path:
    """``$NEXUS_HOME/control`` or ``~/.nexus/control`` (mirrors ``control.Dir`` in Go)."""
    home = os.environ.get(ENV_HOME)
    if home:
        return Path(home) / "control"
    return Path.home() / ".nexus" / "control"


def pid_alive(pid: int) -> bool:
    """Best-effort check that a process exists. Unknown PIDs (<= 0) count as alive."""
    if pid <= 0:
        return True
    if sys.platform == "win32":  # pragma: no cover - os.kill(pid, 0) would terminate on Windows
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def from_env() -> Optional[ControlInfo]:
    """The endpoint named by ``NEXUS_CONTROL_URL``/``NEXUS_CONTROL_TOKEN`` (set by ``nexus-cli run``)."""
    raw = os.environ.get(ENV_CONTROL_URL, "").strip()
    if not raw:
        return None
    token = os.environ.get(ENV_CONTROL_TOKEN, "").strip()
    u = urlparse(raw)
    if u.scheme != "http" or not u.netloc:
        raise DaemonNotFoundError(f"invalid {ENV_CONTROL_URL} {raw!r} (want http://host:port)")
    if not token:
        raise DaemonNotFoundError(f"{ENV_CONTROL_URL} is set but {ENV_CONTROL_TOKEN} is empty")
    return ControlInfo(addr=u.netloc, token=token)


def list_endpoints(directory: Optional[Path] = None) -> List[ControlInfo]:
    """All discovery entries whose process is alive, newest first."""
    d = directory or control_dir()
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    out: List[ControlInfo] = []
    for name in names:
        if not name.endswith(".json") or name.startswith("."):
            continue
        try:
            with open(d / name, encoding="utf-8") as f:
                info = ControlInfo.from_dict(json.load(f))
        except (OSError, ValueError, TypeError, AttributeError):
            continue
        if not info.addr or not info.token or not pid_alive(info.pid):
            continue
        out.append(info)
    out.sort(key=lambda i: i.started_at, reverse=True)
    return out


def discover(kind: Optional[str] = None, pid: Optional[int] = None, *, use_env: bool = True) -> ControlInfo:
    """Find the control endpoint to talk to.

    Order: ``NEXUS_CONTROL_URL`` + ``NEXUS_CONTROL_TOKEN`` (which win over the filters); else the newest live entry in
    ``$NEXUS_HOME/control/*.json`` (or ``~/.nexus/control/*.json``), optionally filtered by
    ``kind`` (``dev``/``run``/``mcp``) and ``pid``. Raises :class:`DaemonNotFoundError`.
    """
    if use_env:
        info = from_env()
        if info is not None:
            return info
    for info in list_endpoints():
        if kind is not None and info.kind != kind:
            continue
        if pid is not None and info.pid != pid:
            continue
        return info
    where = control_dir()
    filt = "".join(f" {k}={v}" for k, v in (("kind", kind), ("pid", pid)) if v is not None)
    raise DaemonNotFoundError(
        f"no running nexus-cli control endpoint found{filt} (set {ENV_CONTROL_URL} or start `nexus-cli dev`; looked in {where})"
    )
