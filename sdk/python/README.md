# Nexus Agent SDK (Python)

Gate AI agent tool calls through [`nexus-cli`](https://github.com/whoisnjoguu/nexus-cli)'s
least-privilege policy, dual-actor identity, human-in-the-loop approval and tamper-evident audit
log.

The SDK asks a running `nexus-cli dev`, `nexus-cli run` or `nexus-cli mcp serve` through its
loopback control API (`POST /v1/check`). The call goes through the same policy engine as that
process's proxy and MCP traffic, so these all apply:

- session taint tracking, so read-then-exfiltrate is caught;
- `one_time` rules;
- "approve for session" grants;
- approvals in the terminal or via `nexus-cli approve`;
- the audit log.

When no daemon is running, `PolicyGate`/`guard` fall back to the stateless
`nexus-cli policy test`.

The core is standard-library only (`urllib`). Python ≥ 3.9, fully typed (`py.typed`).

## Install

```bash
pip install nexus-agent-sdk               # core (stdlib only)
pip install "nexus-agent-sdk[requests]"   # + requests_session()
pip install "nexus-agent-sdk[httpx]"      # + httpx_client() / async_httpx_client()
pip install "nexus-agent-sdk[all]"        # both
```

## Check a tool call against the running daemon

```python
import nexus

nx = nexus.Client()  # discovers the running nexus-cli (see "Discovery")

d = nx.check(tool="fs__write", args={"path": "/etc/passwd"})
print(d.decision, d.reason, d.rule, d.source)   # e.g. deny … tool=fs__write args[path]=/etc/** -> deny policy

nx.require(tool="shell__exec", args={"cmd": "ls"})  # raises nexus.DeniedError unless allowed

# HTTP requests are checked the same way:
nx.check(method="POST", host="api.internal.company.com", path="/v1/payouts/execute")
```

A call that needs human approval blocks until someone decides or the daemon's approval timeout
expires. The client timeout defaults to 600 s. To avoid blocking, pass `wait`:

```python
d = nx.check(tool="deploy", args={"env": "prod"}, wait=0)   # or wait="5s"
if d.pending:
    print("approve with: nexus-cli approve", d.approval_id)
    d = nx.poll(d.approval_id, wait="60s")                 # long-poll, max 60 s per call
```

Other methods:

- `nx.approvals()`: pending approval requests.
- `nx.decide(id, "once" | "session" | "always" | "deny")`.
- `nx.status()`: kind, pid, proxy `listen` address and the number of pending approvals.

`Decision` fields:

| Field         | Meaning                                                               |
| ------------- | --------------------------------------------------------------------- |
| `allowed`     | `True` only for an explicit allow. Anything else must abort the call. |
| `decision`    | `allow`, `deny`, or `pending` (only with `wait=`).                    |
| `reason`      | Human-readable reason, as written to the audit log.                   |
| `rule`        | Label of the rule that matched, e.g. `tool=fs__write -> allow`.       |
| `source`      | `policy`, `approve` (human), `default` (no rule matched) or `guard`.  |
| `approval_id` | Set when the call went to human-in-the-loop.                          |

Identity: `Client(agent_id=..., act_as=..., session=...)` sets defaults, and every `check()` can
override them. When a nexus JWT is available (`token=`, `NEXUS_TOKEN`, or the password in
`NEXUS_PROXY_URL` that `nexus-cli run` exports), it is sent along and is authoritative for the
agent identity and scopes. Daemons that require auth deny checks without one: `dev` does by
default (`--require-auth`), and `run` always does. Mint a token with `nexus-cli identity mint`
and export it as `NEXUS_TOKEN`.

### asyncio

```python
nx = nexus.AsyncClient()
d = await nx.check(tool="fs__read", args={"path": "README.md"})
await nx.require(tool="shell__exec", args={"cmd": "ls"})
```

`AsyncClient` runs the stdlib client in a worker thread (`asyncio.to_thread`).

## Gate a tool function

```python
from nexus import guard, DeniedError

@guard(tool="fs__write", args_from=["path"])   # policy args: {"path": ...}
def write_file(path: str, content: str) -> None:
    ...

@guard(tool="shell__exec")                      # policy args: all arguments, {"cmd": ...}
async def run_shell(cmd: str) -> str:
    ...

try:
    write_file("/etc/passwd", "x")
except DeniedError as e:
    print("blocked:", e, e.decision.rule)
```

`guard` works on sync and async functions; a denied function never runs. `args_from` maps the
function's arguments to the policy's `args` (for `args:` matchers in `nexus.yaml`). It takes one
of:

- nothing: all bound arguments, without `self`/`cls`, with `**kwargs` flattened;
- a list of parameter names;
- a mapping `{policy_arg: parameter}`;
- a callable with the function's signature that returns a dict.

Without an explicit gate, `guard` uses `nexus.default_gate()`, a shared `PolicyGate()`. Replace
it with `nexus.set_default_gate(...)`.

### `PolicyGate` modes

```python
from nexus import PolicyGate, ToolCall, guard

gate = PolicyGate(mode="auto")        # daemon when discoverable, else `nexus-cli policy test`
gate = PolicyGate(mode="daemon")      # require a running daemon (DaemonNotFoundError otherwise)
gate = PolicyGate("nexus-cli", "nexus.yaml", mode="subprocess")  # the 0.1 behaviour

decision = gate.authorize(ToolCall(tool="fs__write", args={"path": "/tmp/x"}))

@guard(gate, tool="execute_shell")
def execute_shell(cmd: str) -> str:
    ...
```

`auto` mode decides once, on first use. In daemon mode, a daemon that is unreachable or returns
an error denies the call (fail closed). Subprocess mode is stateless: taint tracking, one_time
rules and approvals need the daemon, and tool `args` are not evaluated there.

## Route HTTP through the proxy

```python
import nexus

s = nexus.requests_session()     # requests.Session
c = nexus.httpx_client()         # httpx.Client
ac = nexus.async_httpx_client()  # httpx.AsyncClient
```

The proxy is resolved in this order:

1. `NEXUS_PROXY_URL`, then `HTTPS_PROXY`/`HTTP_PROXY`. `nexus-cli run` sets these, with the
   agent token as the proxy password.
2. Otherwise, the discovered daemon's proxy `listen` address, with `token=` or `NEXUS_TOKEN` as
   the proxy credentials.

TLS verification uses the bundle that trusts the nexus MITM CA, read from `NEXUS_CA_BUNDLE`, then
`REQUESTS_CA_BUNDLE`, then `SSL_CERT_FILE`. If none is set, the system CAs are used. Pass
`proxy=` or `verify=` to override.

The older `nexus.httpx_transport.client(token_source, proxy_url)`, which sends a fresh bearer
token per request, still works.

## Discovery

`nexus.Client()` and `PolicyGate(mode="auto")` find the daemon in this order:

1. `NEXUS_CONTROL_URL` + `NEXUS_CONTROL_TOKEN`. `nexus-cli run` exports these to the command it
   launches.
2. The newest live entry in `$NEXUS_HOME/control/*.json`, or in `~/.nexus/control/*.json`. Files
   whose PID is no longer running are skipped. Narrow the search with
   `nexus.Client(kind="mcp")` or `nexus.Client(pid=1234)`.

To connect explicitly, use `nexus.Client(url="http://127.0.0.1:PORT", control_token="...")`.

## Environment variables

| Variable                                                 | Used for                                                 |
| -------------------------------------------------------- | -------------------------------------------------------- |
| `NEXUS_CONTROL_URL`, `NEXUS_CONTROL_TOKEN`               | Control API endpoint and its bearer token                |
| `NEXUS_HOME`                                             | Discovery directory root (default `~/.nexus`)            |
| `NEXUS_TOKEN`                                            | Nexus JWT sent with checks and used as proxy credentials |
| `NEXUS_PROXY_URL`, `HTTP(S)_PROXY`                       | Proxy for `requests_session()` / `httpx_client()`        |
| `NEXUS_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` | CA bundle for TLS through the MITM proxy                 |

## Security model

The control API listens only on `127.0.0.1`. It is protected by a random per-process bearer
token, which is stored in a `0600` discovery file. Anything running as the same OS user can read
that file and therefore ask for decisions or approve requests. The SDK is a guard rail for
cooperative agent code; it does not isolate the agent from code running under your own account.
To hold agents to an identity, require a nexus JWT (`--require-auth`; `run` always does). See
[`docs/sdk.md`](../../docs/sdk.md).
