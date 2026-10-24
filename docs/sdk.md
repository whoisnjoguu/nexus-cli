# SDKs and the daemon decision API

A running `nexus-cli dev`, `nexus-cli run` or `nexus-cli mcp serve` can authorize calls for code
that does not go through its proxy or MCP gateway, for example an in-process tool call made by an
agent framework. The SDKs send these calls to `POST /v1/check` on the process's loopback
**control API**. That is the same API `nexus-cli approve` uses.

A check runs through the same pipeline as proxied HTTP and MCP tool calls, and through the same
`policy.Engine` instance (`pkg/gate`):

1. Identity. An optional nexus JWT is verified and its scopes are applied.
2. Policy evaluation, including `args:` matchers, the egress allowlist and strict mode.
3. Human-in-the-loop approval, when needed, through the process's approvers: the terminal prompt
   and `nexus-cli approve`.
4. `one_time` consumption, "approve for session" grants and "approve always" rule persistence.
5. An audit record.

Because the engine is shared, session state is shared too. Taint stamped by an SDK `fs__read`
check escalates the same session's later proxied egress, and the reverse also holds. A `one_time`
rule consumed through the SDK is consumed for the proxy as well.

```
agent code ──nexus.Client / sdk.Client──▶ 127.0.0.1:<port>/v1/check ──▶ policy · HITL · audit
                                              (control API of dev/run/mcp)      (shared engine)
```

## Discovery

Each running process writes `$NEXUS_HOME/control/<pid>-<rand>.json` (default `~/.nexus/control`),
mode `0600`:

```json
{
  "pid": 4242,
  "addr": "127.0.0.1:49731",
  "token": "<control bearer token>",
  "kind": "dev",
  "started": "2025-01-01T10:00:00Z",
  "listen": "127.0.0.1:8075",
  "policy": "/work/nexus.yaml",
  "cwd": "/work"
}
```

The clients pick the control endpoint in this order:

1. `NEXUS_CONTROL_URL` (`http://127.0.0.1:<port>`) + `NEXUS_CONTROL_TOKEN`. `nexus-cli run`
   exports these to its child process (with the check-only token, so `approvals()`/`decide()`
   are refused there).
2. The newest live discovery file, by `started`. Files whose process has exited are skipped.
   You can filter by `kind` (`dev`, `run` or `mcp`) and by `pid`.

## Environment variables

| Variable                                                 | Meaning                                                                                       |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `NEXUS_CONTROL_URL`                                      | Control API base URL; takes precedence over discovery files                                   |
| `NEXUS_CONTROL_TOKEN`                                    | Bearer token for `NEXUS_CONTROL_URL` (required with it); the check-only token under `run`     |
| `NEXUS_HOME`                                             | Root of the discovery directory (`$NEXUS_HOME/control`); default `~/.nexus`                   |
| `NEXUS_TOKEN`                                            | Nexus JWT sent as `token` with every check, and used as proxy credentials by the HTTP helpers |
| `NEXUS_PROXY_URL`                                        | `http://nexus:<jwt>@host:port`, set by `run`; its password is the fallback for `NEXUS_TOKEN`  |
| `HTTPS_PROXY`, `HTTP_PROXY`                              | Proxy used by the Python `requests_session()` / `httpx_client()` helpers                      |
| `NEXUS_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` | CA bundle trusting the nexus MITM CA (first one set wins)                                     |

## API reference

All endpoints require `Authorization: Bearer <control token>`. A missing or wrong token gets
`401`.

### `POST /v1/check`

Request (`Content-Type: application/json`):

```json
{
  "agent_id": "claims-bot",
  "act_as": "alice@company.com",
  "session": "",
  "token": "<optional nexus JWT>",
  "tool": "fs__write",
  "provider": "",
  "method": "",
  "host": "",
  "path": "",
  "scopes": ["fs:write"],
  "args": { "path": "/tmp/report.md" },
  "wait": ""
}
```

| Field                    | Meaning                                                                                                                                               |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tool`                   | Tool name, matched by `match.tool` rules. Give `tool`, or `method`/`host` (HTTP), or both.                                                            |
| `provider`               | Optional provider, matched by `match.provider`.                                                                                                       |
| `method`, `host`, `path` | An HTTP request, matched like proxied traffic, including the egress allowlist and taint escalation. `method` is upper-cased.                          |
| `args`                   | JSON object (or `null`) matched by `args:` matchers. Its hash is written to the audit log.                                                            |
| `scopes`                 | Scopes the agent holds. With a `token`, these can only narrow the token's scopes.                                                                     |
| `agent_id`, `act_as`     | Identity. Defaults are `anonymous-agent` / `unknown-user`. With a `token` they must match the token's claims, or be empty.                            |
| `session`                | Session key for taint, `one_time` and session grants. Defaults to `agent_id\|act_as`, the key the proxy and MCP gateway use for that identity.        |
| `token`                  | Nexus JWT (`nexus-cli identity mint`), verified with the process's key. An invalid token always denies.                                               |
| `wait`                   | Empty: block until the call is decided. `"0"`: return `pending` at once. A duration (`"5s"`; capped at `60s`): wait that long, then return `pending`. |

Response:

```json
{
  "decision": "allow",
  "reason": "matched rule",
  "rule": "tool=fs__write -> allow",
  "source": "policy",
  "approval_id": ""
}
```

| Field         | Values                                                                                                                                                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `decision`    | `allow`, `deny`, or `pending` (only when `wait` is set).                                                                                                                                                                                    |
| `reason`      | The reason recorded in the audit log, for example: `matched rule`, `no matching rule (default)`, `approved once`, `approved for session`, `session grant`, `denied at human-in-the-loop (approval timed out)`, `a nexus token is required`. |
| `rule`        | Label of the matched rule, e.g. `tool=fs__write args[path]=/etc/** -> deny`.                                                                                                                                                                |
| `source`      | `policy` (a rule decided), `approve` (a human, or a session grant), `default` (no rule matched or the host is not on the egress allowlist) or `guard` (identity problems, or no approver attached).                                         |
| `approval_id` | Set when the call went to human-in-the-loop. It matches the id shown by `nexus-cli approve --list`.                                                                                                                                         |

A blocking check (`wait` empty) can last up to the process's approval timeout (`--approval-timeout`,
default 60s), so give clients a longer timeout. The Python client defaults to 600s and the Go
client has none. If the client disconnects while waiting, the approval is cancelled and the call
is denied and audited (`... (approval cancelled)`).

Status codes:

| Code  | When                                                                                                                                    |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `200` | Decided (`allow` or `deny`).                                                                                                            |
| `202` | `pending`; poll `GET /v1/check/{approval_id}`.                                                                                          |
| `400` | Invalid JSON, unknown fields, trailing data, `args` not an object, invalid `wait`, or neither `tool` nor `method`/`host`.               |
| `401` | Missing or wrong control bearer token.                                                                                                  |
| `413` | Body larger than 64 KiB.                                                                                                                |
| `415` | `Content-Type` is not `application/json`.                                                                                               |
| `503` | The process has no checker attached, or too many approvals (1024) are being tracked for polling. In the second case the call is denied. |

Errors have the body `{"error": "..."}`.

### `GET /v1/check/{approval_id}?wait=30s`

Returns the result of a check that returned `pending`. It responds `202` with
`{"decision":"pending","approval_id":...}` while a human has not decided, and `200` with the final
decision once they have. Unknown ids get `404`. With `wait`, the request long-polls for up to that
long (60s maximum). Results are kept for 10 minutes after the decision.

### Related endpoints

- `GET /v1/status`: discovery info (without the token) plus `pending`.
- `GET /v1/approvals`: pending approval requests.
- `POST /v1/approvals/{id}` with `{"decision": "once|session|always|deny"}`.

## Python

```bash
pip install nexus-agent-sdk            # stdlib-only core
pip install "nexus-agent-sdk[all]"     # + requests and httpx helpers
```

```python
import nexus

nx = nexus.Client()                                  # discovery as above
d = nx.check(tool="fs__write", args={"path": "/etc/passwd"})
d.allowed, d.decision, d.reason, d.rule, d.source, d.approval_id

nx.require(tool="shell__exec", args={"cmd": "ls"})  # raises nexus.DeniedError

d = nx.check(tool="deploy", wait=0)                  # non-blocking
if d.pending:
    d = nx.poll(d.approval_id, wait="30s")

nx.approvals(); nx.decide(approval_id, "once"); nx.status()

anx = nexus.AsyncClient()                            # asyncio (worker thread)
await anx.require(tool="fs__read", args={"path": "README.md"})

@nexus.guard(tool="fs__write", args_from=["path"])  # sync or async functions
def write_file(path: str, content: str) -> None: ...

nexus.PolicyGate(mode="auto" | "daemon" | "subprocess")  # 0.1 API; auto prefers the daemon

session = nexus.requests_session()                   # proxy + CA bundle configured
client = nexus.httpx_client(); aclient = nexus.async_httpx_client()
```

See [`sdk/python/README.md`](../sdk/python/README.md).

## Go

```go
import sdk "github.com/whoisnjoguu/nexus-cli/sdk/go"

c, err := sdk.Connect(sdk.ConnectOptions{})            // or {Kind: "mcp"}, {PID: 4242}; sdk.NewClient(info)
if err != nil { return err }                           // sdk.ErrNoDaemon when nothing is running
c.AgentID, c.ActAs = "claims-bot", "alice@company.com" // defaults; c.Token defaults to NEXUS_TOKEN

resp, err := c.Check(ctx, sdk.CheckRequest{Tool: "fs__write", Args: json.RawMessage(`{"path":"/tmp/x"}`)})
if err == nil && resp.Allowed() { ... }

if err := c.Require(ctx, sdk.CheckRequest{Tool: "shell__exec"}); err != nil {
    var denied *sdk.DeniedError                        // errors.As(err, &denied) → denied.Response
}

resp, _ = c.Check(ctx, sdk.CheckRequest{Tool: "deploy", Wait: "0"})
resp, _ = c.Poll(ctx, resp.ApprovalID, 30*time.Second)

// *sdk.Client implements sdk.Gate, so it can back the gating transport:
hc := &http.Client{Transport: &sdk.GateTransport{Gate: c, Agent: "claims-bot", ActAs: "alice@company.com"}}
```

`Status`, `Approvals` and `Decide` wrap the other control endpoints. The in-process `LocalGate`,
which embeds its own engine with no daemon, is still available. `ToolCall.Args` now feeds
`args:` matchers there as well.

## Security model

- **Same-user trust boundary.** The control API binds only to `127.0.0.1`. It rejects requests
  whose `Host` header is not its own address (DNS rebinding), and requires a 256-bit random bearer
  token. There are two tokens:
  - the **admin token**, stored in the `0600` discovery file, which can also list and answer
    approvals;
  - the **check token**, which only authorizes `POST /v1/check`, `GET /v1/check/{id}` and
    `GET /v1/status`. This is the token `run` passes to its child in `NEXUS_CONTROL_TOKEN`, so a
    gated agent can ask for decisions but cannot approve its own requests through the API.

  Any process running as your OS user can still read the discovery file. The SDK is a policy
  guard rail for cooperative agent code, not a sandbox against hostile code running under your
  account. Run untrusted agents as a different user or in a container, and give them only the
  proxy and the check token.

- **Agent identity.** Without a JWT, `agent_id`/`act_as` are self-asserted. With `token`, the
  verified claims are authoritative: mismatching `agent_id`/`act_as` are denied, and `scopes`
  can only narrow. Processes that require auth (`dev`'s default `--require-auth`, and `run`)
  deny checks without a valid token. Single-use tokens are consumed by a check, just as they
  would be by a proxied request.
- **Fail closed.** Invalid tokens, unknown fields, oversized bodies and approvals that time out
  or are cancelled all deny. The Python `PolicyGate` denies when the daemon is unreachable.
- **Audit.** Every check is recorded exactly like proxy and MCP decisions, with the tool,
  target (`sdk:<tool>` or `host/path`), decision, reason, rule, source, session and an arguments
  hash, in the same hash chain (`nexus-cli audit tail`/`verify`).
