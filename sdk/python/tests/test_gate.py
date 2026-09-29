import subprocess
from unittest import mock

from nexus import Decision, DeniedError, PolicyGate, ToolCall, guard


def _completed(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_policy_gate_parses_allow():
    gate = PolicyGate(binary="nexus-cli")
    with mock.patch("subprocess.run", return_value=_completed("Decision: ALLOW\nReason:   matched rule\n")):
        dec = gate.authorize(ToolCall(method="GET", host="api.internal.company.com", path="/v1/x", scopes=["db:read"]))
    assert dec == Decision(allowed=True, reason="matched rule")


def test_policy_gate_parses_deny():
    gate = PolicyGate()
    with mock.patch("subprocess.run", return_value=_completed("Decision: DENY\nReason:   no matching rule (default)\n")):
        dec = gate.authorize(ToolCall(tool="execute_shell"))
    assert not dec.allowed


def test_guard_raises_on_deny():
    gate = PolicyGate()

    @guard(gate, tool="execute_shell")
    def execute_shell(cmd: str) -> str:
        return cmd

    with mock.patch("subprocess.run", return_value=_completed("Decision: DENY\nReason:   blocked\n")):
        try:
            execute_shell("rm -rf /")
            assert False, "expected DeniedError"
        except DeniedError as exc:
            assert "execute_shell" in str(exc)


def test_guard_allows():
    gate = PolicyGate()

    @guard(gate, tool="read_file", method="GET")
    def read_file(path: str) -> str:
        return f"contents of {path}"

    with mock.patch("subprocess.run", return_value=_completed("Decision: ALLOW\nReason:   ok\n")):
        assert read_file("/etc/hosts") == "contents of /etc/hosts"
