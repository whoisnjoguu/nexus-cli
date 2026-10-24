import asyncio
import os

import pytest

import nexus
from conftest import FakeDaemon, write_discovery

ALLOW = {"decision": "allow", "reason": "matched rule", "rule": "tool=fs__read", "source": "policy"}
DENY = {"decision": "deny", "reason": "denied by rule", "rule": "tool=shell__exec", "source": "policy"}


def test_check_sends_bearer_and_body(daemon_env):
    daemon_env.decide_by_tool({"fs__read": ALLOW})
    c = nexus.Client(agent_id="bot", act_as="alice", session="s1", token="jwt")
    d = c.check(tool="fs__read", args={"path": "/x", "n": 1}, scopes=["fs:read"])
    assert d == nexus.Decision(allowed=True, reason="matched rule", decision="allow", rule="tool=fs__read",
                               source="policy")
    req = daemon_env.requests[-1]
    assert req["headers"]["Authorization"] == "Bearer ctl-secret"
    assert req["headers"]["Content-Type"] == "application/json"
    assert req["body"] == {"agent_id": "bot", "act_as": "alice", "session": "s1", "token": "jwt",
                           "tool": "fs__read", "args": {"path": "/x", "n": 1}, "scopes": ["fs:read"]}


def test_check_http_request_and_overrides(daemon_env):
    daemon_env.on("POST", "/v1/check", lambda r: (200, DENY))
    c = nexus.Client(agent_id="bot")
    d = c.check(method="post", host="api.example.com", path="/v1", agent_id="other", wait=0)
    assert not d.allowed and d.decision == "deny" and d.source == "policy"
    assert daemon_env.checks()[-1] == {"agent_id": "other", "method": "post", "host": "api.example.com",
                                       "path": "/v1", "wait": "0"}


def test_require(daemon_env):
    daemon_env.decide_by_tool({"fs__read": ALLOW, "shell__exec": DENY})
    c = nexus.Client()
    assert c.require("fs__read").allowed
    with pytest.raises(nexus.DeniedError, match="nexus denied shell__exec: denied by rule") as ei:
        c.require("shell__exec", {"cmd": "rm"})
    assert ei.value.decision.rule == "tool=shell__exec"


def test_pending_and_poll(daemon_env):
    daemon_env.on("POST", "/v1/check", lambda r: (202, {"decision": "pending", "approval_id": "abc"}))
    daemon_env.on("GET", "/v1/check/abc", lambda r: (200, {"decision": "allow", "reason": "approved once",
                                                           "source": "approve", "approval_id": "abc"}))
    c = nexus.Client()
    d = c.check("deploy", wait="0")
    assert d.pending and not d.allowed and d.approval_id == "abc"
    with pytest.raises(nexus.DeniedError, match="pending approval abc"):
        c.require("deploy", wait=0)
    d2 = c.poll("abc", wait=2.5)
    assert d2.allowed and d2.source == "approve"
    assert daemon_env.requests[-1]["query"] == "wait=2.5s"
    with pytest.raises(nexus.NexusError):
        c.poll("../x")


def test_errors(daemon_env, monkeypatch):
    daemon_env.on("POST", "/v1/check", lambda r: (400, {"error": "invalid JSON body"}))
    c = nexus.Client()
    with pytest.raises(nexus.ApiError) as ei:
        c.check("x")
    assert ei.value.status == 400 and "invalid JSON body" in str(ei.value)
    with pytest.raises(nexus.ApiError) as ei:
        c.poll("missing")
    assert ei.value.status == 404

    bad = nexus.Client(url=daemon_env.url, control_token="wrong")
    with pytest.raises(nexus.UnauthorizedError):
        bad.status()

    with pytest.raises(nexus.NexusError):
        nexus.Client(url=daemon_env.url)
    dead = nexus.Client(url="http://127.0.0.1:1", control_token="t", timeout=2)
    with pytest.raises(nexus.NexusError):
        dead.check("x")


def test_ignores_proxy_env(daemon_env, monkeypatch):
    # The control API is loopback; HTTP(S)_PROXY (which `run` points at nexus itself) must not apply.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    daemon_env.decide_by_tool({"t": ALLOW})
    assert nexus.Client().check("t").allowed


def test_token_from_env(daemon_env, monkeypatch):
    daemon_env.decide_by_tool({})
    monkeypatch.setenv("NEXUS_PROXY_URL", "http://nexus:proxyjwt@127.0.0.1:8075")
    nexus.Client().check("t")
    assert daemon_env.checks()[-1]["token"] == "proxyjwt"
    monkeypatch.setenv("NEXUS_TOKEN", "envjwt")
    nexus.Client().check("t")
    assert daemon_env.checks()[-1]["token"] == "envjwt"
    nexus.Client(token="").check("t")
    assert "token" not in daemon_env.checks()[-1]


def test_approvals_status_decide(daemon_env):
    daemon_env.on("GET", "/v1/approvals", lambda r: (200, [{"id": "a1", "agent_id": "bot", "act_as": "alice",
                                                             "tool": "deploy", "target": "sdk:deploy",
                                                             "reason": "hitl", "created": "2024-01-01T00:00:00Z"}]))
    daemon_env.on("POST", "/v1/approvals/a1", lambda r: (204, None))
    c = nexus.Client()
    [a] = c.approvals()
    assert (a.id, a.tool, a.act_as) == ("a1", "deploy", "alice")
    c.decide("a1", "once")
    assert daemon_env.requests[-1]["body"] == {"decision": "once"}
    with pytest.raises(ValueError):
        c.decide("a1", "maybe")
    st = c.status()
    assert st.kind == "dev" and st.listen == "127.0.0.1:8075" and st.pid == os.getpid()


def test_unserializable_args_are_stringified(daemon_env):
    daemon_env.decide_by_tool({})
    nexus.Client().check("t", {"obj": object.__new__(type("X", (), {"__str__": lambda s: "X!"}))})
    assert daemon_env.checks()[-1]["args"] == {"obj": "X!"}


def test_async_client(daemon_env):
    daemon_env.decide_by_tool({"fs__read": ALLOW, "shell__exec": DENY})

    async def main():
        c = nexus.AsyncClient(agent_id="bot")
        results = await asyncio.gather(c.check("fs__read", {"p": 1}), c.check("shell__exec"))
        with pytest.raises(nexus.DeniedError):
            await c.require("shell__exec")
        st = await c.status()
        return results, st

    (a, d), st = asyncio.run(main())
    assert a.allowed and not d.allowed and st.kind == "dev"
    assert all(b["agent_id"] == "bot" for b in daemon_env.checks())


def test_explicit_info(daemon, isolated_env):
    write_discovery(isolated_env, "x", pid=os.getpid(), addr="127.0.0.1:1", token="nope", kind="dev")
    c = nexus.Client(info=nexus.ControlInfo(addr=daemon.addr, token=FakeDaemon.TOKEN))
    assert c.status().kind == "dev"
