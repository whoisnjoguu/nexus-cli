import asyncio
import inspect
import subprocess
from unittest import mock

import pytest

import nexus
from nexus import DeniedError, PolicyGate, ToolCall, guard

ALLOW = {"decision": "allow", "reason": "ok", "source": "policy"}


def test_auto_prefers_daemon(daemon_env):
    daemon_env.decide_by_tool({"fs__write": ALLOW})
    gate = PolicyGate()
    with mock.patch("subprocess.run") as run:
        d = gate.authorize(ToolCall(tool="fs__write", args={"path": "/tmp/x"}, scopes=["fs:write"]))
    run.assert_not_called()
    assert d.allowed and gate.mode == "daemon" and gate.client is not None
    # A tool call does not send the decorator's default method.
    assert daemon_env.checks()[-1] == {"tool": "fs__write", "args": {"path": "/tmp/x"}, "scopes": ["fs:write"]}


def test_http_call_via_daemon(daemon_env):
    daemon_env.on("POST", "/v1/check", lambda r: (200, ALLOW))
    PolicyGate(mode="daemon").authorize(ToolCall(method="GET", host="api.x.com", path="/v1"))
    assert daemon_env.checks()[-1] == {"method": "GET", "host": "api.x.com", "path": "/v1"}


def test_auto_falls_back_to_subprocess():
    gate = PolicyGate()
    out = subprocess.CompletedProcess(args=[], returncode=0, stdout="Decision: ALLOW\nReason: ok\n", stderr="")
    with mock.patch("subprocess.run", return_value=out) as run:
        assert gate.authorize(ToolCall(tool="t")).allowed
    run.assert_called_once()
    assert gate.mode == "subprocess"


def test_daemon_mode_requires_daemon():
    with pytest.raises(nexus.DaemonNotFoundError):
        PolicyGate(mode="daemon").authorize(ToolCall(tool="t"))
    with pytest.raises(ValueError):
        PolicyGate(mode="bogus")


def test_subprocess_mode_ignores_daemon(daemon_env):
    out = subprocess.CompletedProcess(args=[], returncode=0, stdout="Decision: DENY\nReason: nope\n", stderr="")
    with mock.patch("subprocess.run", return_value=out):
        assert not PolicyGate(mode="subprocess").authorize(ToolCall(tool="t")).allowed
    assert daemon_env.checks() == []


def test_daemon_failure_fails_closed():
    c = nexus.Client(url="http://127.0.0.1:1", control_token="t", timeout=2)
    d = PolicyGate(client=c).authorize(ToolCall(tool="t"))
    assert not d.allowed and d.source == "guard"


def test_guard_sync_default_gate_and_args(daemon_env):
    daemon_env.decide_by_tool({"fs__write": ALLOW})
    calls = []

    @guard(tool="fs__write")
    def write(path, content="", *, mode="w", **extra):
        calls.append(path)
        return len(content)

    assert write("/a", "hello", flag=True) == 5
    assert daemon_env.checks()[-1]["args"] == {"path": "/a", "content": "hello", "mode": "w", "flag": True}

    @guard(tool="shell__exec")
    def shell(cmd):
        calls.append(cmd)

    with pytest.raises(DeniedError, match="nexus denied shell__exec: no matching rule") as ei:
        shell("rm -rf /")
    assert ei.value.decision.source == "default"
    assert calls == ["/a"]  # the denied function never ran


@pytest.mark.parametrize(
    "args_from,expected",
    [
        (["path"], {"path": "/a"}),
        ("path", {"path": "/a"}),
        ({"file": "path", "missing": "nope"}, {"file": "/a"}),
        (lambda path, content: {"p": path.upper()}, {"p": "/A"}),
    ],
)
def test_guard_args_from(daemon_env, args_from, expected):
    daemon_env.decide_by_tool({"fs__write": ALLOW})

    @guard(tool="fs__write", args_from=args_from)
    def write(path, content):
        return content

    assert write("/a", content="secret") == "secret"
    assert daemon_env.checks()[-1]["args"] == expected


def test_guard_method_drops_self(daemon_env):
    daemon_env.decide_by_tool({"Tool.run": ALLOW})

    class Tool:
        @guard(tool="Tool.run")
        def run(self, q):
            return q

    assert Tool().run("x") == "x"
    assert daemon_env.checks()[-1]["args"] == {"q": "x"}


def test_guard_async(daemon_env):
    daemon_env.decide_by_tool({"fetch": ALLOW})
    ran = []

    @guard(tool="fetch", args_from=["url"])
    async def fetch(url, retries=3):
        ran.append(url)
        await asyncio.sleep(0)
        return url

    @guard(tool="nuke")
    async def nuke():
        ran.append("nuke")

    assert inspect.iscoroutinefunction(fetch)
    assert asyncio.run(fetch("https://x")) == "https://x"
    with pytest.raises(DeniedError):
        asyncio.run(nuke())
    assert ran == ["https://x"]
    assert daemon_env.checks()[0]["args"] == {"url": "https://x"}


def test_guard_async_with_plain_gate():
    class Gate:
        def __init__(self):
            self.calls = []

        def authorize(self, call):
            self.calls.append(call)
            return nexus.Decision(allowed=call.tool == "ok", reason="custom")

    g = Gate()

    @guard(g, tool="ok")
    async def ok(x):
        return x * 2

    @guard(g, tool="no")
    async def no():
        return 1

    assert asyncio.run(ok(2)) == 4
    with pytest.raises(DeniedError, match="custom"):
        asyncio.run(no())
    assert g.calls[0].args == {"x": 2}


def test_set_default_gate():
    class Deny:
        def authorize(self, call):
            return nexus.Decision(allowed=False, reason="by default gate")

    nexus.set_default_gate(Deny())

    @guard(tool="t")
    def f():
        return 1

    with pytest.raises(DeniedError, match="by default gate"):
        f()
