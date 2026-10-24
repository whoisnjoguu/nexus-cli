import os
import subprocess
import sys

import pytest

import nexus
from conftest import write_discovery


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def test_env_wins(isolated_env, monkeypatch):
    write_discovery(isolated_env, "1", pid=os.getpid(), addr="127.0.0.1:1111", token="file", kind="dev",
                    started="2030-01-01T00:00:00Z")
    monkeypatch.setenv("NEXUS_CONTROL_URL", "http://127.0.0.1:2222")
    monkeypatch.setenv("NEXUS_CONTROL_TOKEN", "envtok")
    info = nexus.discover()
    assert (info.addr, info.token) == ("127.0.0.1:2222", "envtok")
    assert nexus.discover(kind="mcp").addr == "127.0.0.1:2222"


@pytest.mark.parametrize("url,token", [("ftp://x:1", "t"), ("http://", "t"), ("http://127.0.0.1:1", "")])
def test_env_invalid(monkeypatch, url, token):
    monkeypatch.setenv("NEXUS_CONTROL_URL", url)
    monkeypatch.setenv("NEXUS_CONTROL_TOKEN", token)
    with pytest.raises(nexus.DaemonNotFoundError):
        nexus.discover()


def test_files_newest_live_entry(isolated_env):
    me = os.getpid()
    write_discovery(isolated_env, "old", pid=me, addr="127.0.0.1:1001", token="a", kind="dev",
                    started="2024-01-01T10:00:00.123456789Z")
    write_discovery(isolated_env, "new", pid=me, addr="127.0.0.1:1002", token="b", kind="mcp",
                    started="2024-01-01T11:00:00.5+02:00")
    write_discovery(isolated_env, "newest", pid=me, addr="127.0.0.1:1003", token="c", kind="run",
                    started="2024-01-01T10:30:00Z")
    write_discovery(isolated_env, "dead", pid=_dead_pid(), addr="127.0.0.1:1004", token="d", kind="dev",
                    started="2099-01-01T00:00:00Z")
    (isolated_env / "control" / "junk.json").write_text("{not json")
    (isolated_env / "control" / "notoken.json").write_text('{"addr":"127.0.0.1:9","pid":1}')
    (isolated_env / "control" / ".hidden.json").write_text('{"addr":"127.0.0.1:9","token":"x"}')

    # 11:00+02:00 == 09:00Z, so the run endpoint (10:30Z) is the newest live one.
    assert [i.addr for i in nexus.list_endpoints()] == ["127.0.0.1:1003", "127.0.0.1:1001", "127.0.0.1:1002"]
    assert nexus.discover().token == "c"
    assert nexus.discover(kind="dev").token == "a"
    assert nexus.discover(kind="mcp").token == "b"
    assert nexus.discover(pid=me).token == "c"
    with pytest.raises(nexus.DaemonNotFoundError):
        nexus.discover(pid=me + 1_000_000)


def test_dead_pid_skipped(isolated_env):
    write_discovery(isolated_env, "dead", pid=_dead_pid(), addr="127.0.0.1:1004", token="d", kind="dev")
    with pytest.raises(nexus.DaemonNotFoundError, match="no running nexus-cli"):
        nexus.discover()


def test_default_dir_is_home_dot_nexus(monkeypatch, tmp_path):
    monkeypatch.delenv("NEXUS_HOME")
    monkeypatch.setenv("HOME", str(tmp_path))
    write_discovery(tmp_path / ".nexus", "x", pid=os.getpid(), addr="127.0.0.1:1", token="t", kind="dev")
    assert nexus.discover().addr == "127.0.0.1:1"


def test_client_uses_discovery(isolated_env, daemon):
    write_discovery(isolated_env, "x", pid=os.getpid(), addr=daemon.addr, token=daemon.TOKEN, kind="dev",
                    listen="127.0.0.1:8075")
    c = nexus.Client()
    assert c.info.kind == "dev"
    assert c.status().pending == 0
