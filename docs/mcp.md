# MCP gateway

`nexus-cli mcp serve` is an MCP server that sits between an agent host (Claude Code, VS Code,
Cursor, …) and any number of **upstream** MCP servers. Every tool call, resource read, prompt
fetch and upstream sampling request is checked against the same `nexus.yaml` policy as the HTTP
proxy: it can be allowed, denied, or sent to a human (HITL), and every decision is written to the
tamper-evident audit log.

```
agent host ──stdio or Streamable HTTP──▶ nexus-cli mcp serve ──stdio──▶ fs (npx …)
                                              │  policy · HITL · audit ──HTTP──▶ https://mcp.example.com/mcp
```

## Configuration

Upstreams live under `mcp.upstreams` in `nexus.yaml`:

```yaml
mcp:
  upstreams:
    - name: fs # tools are exposed as fs__<tool>; prompts as fs__<prompt>
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
      env: { NODE_OPTIONS: "--max-old-space-size=512" } # added to the inherited environment
      cwd: /workspace # working directory of the process (optional)
    - name: remote # Streamable HTTP upstream
      url: https://mcp.example.com/mcp
      headers:
        Authorization: "Bearer ${EXAMPLE_MCP_TOKEN}" # ${VAR} is expanded from the environment
    - name: old
      command: some-server
      disabled: true # keep the entry but don't start it
    - name: flaky
      command: flaky-server
      no_restart: true # leave it down if it exits
```

| Field        | Meaning                                                                                   |
| ------------ | ----------------------------------------------------------------------------------------- |
| `name`       | Required, unique, no `__`. Used as the tool/prompt prefix and as the policy `provider`.   |
| `command`    | Executable for a stdio upstream (exactly one of `command` / `url`).                       |
| `args`       | Arguments for `command`.                                                                  |
| `env`        | Extra environment variables for the process (the gateway's environment is inherited).     |
| `cwd`        | Working directory for the process.                                                        |
| `url`        | Endpoint of a Streamable HTTP upstream.                                                   |
| `headers`    | Extra HTTP headers; `${VAR}` references are expanded so tokens need not live in the yaml. |
| `disabled`   | Skip this upstream.                                                                       |
| `no_restart` | Leave this upstream `down` when it exits instead of restarting it (see `--no-restart`).   |

### `mcp serve` flags

| Flag                     | Default                                      | Meaning                                                                                                                                         |
| ------------------------ | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `--policy`               | see below                                    | Policy + upstream config. Default: `$NEXUS_POLICY`, else `$NEXUS_HOME/policy.yaml` if it exists, else `./nexus.yaml`.                           |
| `--strict`               | off                                          | Every tool call needs approval.                                                                                                                 |
| `--http ADDR`            | (stdio)                                      | Serve Streamable HTTP at `http://ADDR/mcp` instead of stdio.                                                                                    |
| `--stdio`                | off                                          | With `--http`, serve stdio as well.                                                                                                             |
| `--http-token`           | generated                                    | Bearer token for HTTP clients. Generated tokens are printed to stderr and written to `<nexus home>/mcp/http.token` (0600, removed on exit).     |
| `--http-allowed-host`    | none                                         | Extra `Host` header values accepted (needed when binding a non-loopback address behind a name).                                                 |
| `--call-timeout`         | `5m`                                         | Per-request timeout for anything forwarded to an upstream. On timeout the upstream gets `notifications/cancelled` and the client gets an error. |
| `--approval-timeout`     | `2m`                                         | How long a HITL prompt waits before it is treated as a denial.                                                                                  |
| `--no-restart`           | off                                          | Don't restart upstreams that exit.                                                                                                              |
| `--no-reload`            | off                                          | Disable policy hot reload (file polling and SIGHUP).                                                                                            |
| `--ephemeral-state`      | off                                          | Keep `one_time` and taint state in memory only.                                                                                                 |
| `--accept-policy-change` | off                                          | Accept and re-pin a policy whose hash differs from `$NEXUS_HOME/policy.pin`.                                                                    |
| `--agent-id`             | `mcp-agent`                                  | Agent identity tool calls are attributed to. `act_as` is the logged-in principal (`unknown-user` when not logged in).                           |
| `--key`                  | `$NEXUS_HOME/ed25519.key`                    | Signing key path (keychain-backed by default, see [keys.md](keys.md)).                                                                          |
| `--gateway`              | `$NEXUS_GATEWAY_URL`, else the login session | nexus-framework Gateway used by the broker-access tools.                                                                                        |
| `--notify`               | `auto`                                       | Desktop notifications for pending approvals (`off`, or `NEXUS_NOTIFY=off`, disables them).                                                      |
| `--no-audit`             | off                                          | Disable the audit log.                                                                                                                          |

`<nexus home>` is `$NEXUS_HOME` or `~/.nexus`.

## Policy for MCP traffic

Upstream tool calls are evaluated as `tool: <upstream>__<tool>` with the tool arguments available
to argument rules. Other gated MCP methods use the method name as the tool and the upstream name as
the provider:

| Traffic                           | `tool`                   | `provider` | `args`              |
| --------------------------------- | ------------------------ | ---------- | ------------------- |
| `tools/call`                      | `fs__write_file`         | –          | the call arguments  |
| `resources/read`                  | `resources/read`         | upstream   | `{uri}`             |
| `prompts/get`                     | `prompts/get`            | upstream   | `{name, arguments}` |
| upstream `sampling/createMessage` | `sampling/createMessage` | upstream   | the sampling params |

The default policy allows `resources/read` and `prompts/get` and sends `sampling/createMessage`
to a human: an upstream asking the host's LLM to generate text is a prompt-injection vector.

### Protected files

Before any rule is evaluated, a built-in guard denies tool calls whose arguments (searched
recursively) name a path inside the active policy file, the policy pin, `$NEXUS_HOME` or the
audit log directory — relative paths, `..` and symlinks included. The reason is
`protected nexus file`. The policy hot-reloads on change (or SIGHUP) and is checked against its
pin; see [policy.md](policy.md).

### Argument rules

A tool rule may constrain the arguments with `args`. Every key must match (logical AND):

```yaml
tools:
  - match: { tool: "fs__write_file", args: { path: "/workspace/**" } }
    action: allow
  - match: { tool: "fs__write_file" }
    action: deny # writes anywhere else
  - match: { tool: "db__query", args: { sql: "!*drop*" } }
    action: allow # anything not containing DROP (case-insensitive)
  - match: { tool: "fs__edit_file", args: { "options.mode": "dry-run" } }
    action: allow # dot paths reach into nested objects
```

- **Keys** are dot paths into the arguments object (`path`, `options.mode`).
- **Values** are glob patterns (`*`, `?`, `[…]`); a leading `!` negates the pattern.
- **Path patterns** (starting with `/`, `~` or `./`) are matched against the cleaned argument
  (`filepath.Clean`), `~` expands to your home directory, and `**` spans directories. So
  `/workspace/../etc/passwd` does **not** match `/workspace/**`. Path patterns are case-sensitive;
  other patterns are case-insensitive.
- **Arrays** match if _any_ element matches; a negated pattern requires that _no_ element matches.
- Numbers and booleans are compared via their string form (`"3"`, `"true"`).
- A missing key never matches (also for negated patterns), so `args` can only narrow a rule.
- `args` is an extra constraint on a tool rule; a match with nothing else in it never matches.
- Session grants ("approve for this session") cover the tool, not specific arguments. "Always"
  grants persist a rule that keeps the `args` of the rule that triggered the prompt.

### Fetch-style tools and egress

If a tool call has a string `url`, `uri` or `endpoint` argument holding an absolute `http(s)` URL,
the call is also evaluated as egress to that host/path. This means the `egress.allow` list and
`escalate_when_tainted` apply to MCP fetch tools: after a tool tagged `taints: [secrets]` runs, a
`fetch__fetch` to a host that is not on the allowlist escalates to HITL instead of silently
exfiltrating data.

## Approvals

When a decision is `hitl`:

1. If the client supports MCP **elicitation**, the gateway asks it (once / session / always / deny).
2. In every case the request is also queued on a local control endpoint, so you can answer it from
   another terminal with **`nexus-cli approve`**. The first answer wins. A hint is logged to stderr
   (never stdout).
3. With neither answering within `--approval-timeout`, the call is denied.

Without elicitation support, HITL calls are therefore no longer auto-denied: they wait for
`nexus-cli approve`.

## Protocol behaviour

- **Version negotiation**: supported protocol versions are `2024-11-05`, `2025-03-26`,
  `2025-06-18` and `2025-11-25`. The gateway echoes the client's requested version when supported,
  otherwise answers with the latest. Upstreams are connected before any client, so the gateway
  offers them the latest version and uses whatever they answer (sent in `MCP-Protocol-Version`
  for HTTP upstreams). `serverInfo.version` is the nexus-cli build version.
- **Capabilities** advertised to the client are the union of the upstreams' capabilities (tools
  always, with `listChanged: true`; resources / prompts / logging / completions when any upstream
  offers them).
- **Concurrency**: each request runs in its own goroutine (max 32 in flight); a slow call or a
  pending approval does not block other requests. `initialize` is handled first.
- **Cancellation**: `notifications/cancelled` from the client (or an HTTP client dropping its POST
  connection) cancels the request and is forwarded to the upstream as `notifications/cancelled`
  with the upstream's request id. No response is sent for a cancelled request.
- **Notifications** from upstreams are forwarded: `notifications/progress` (the client's
  `_meta.progressToken` is passed to the upstream unchanged and progress is routed back to the
  requesting client; only if two in-flight requests use the same token on the same upstream —
  e.g. two HTTP sessions — is the second one replaced by a gateway-unique token, mapped back on
  the way out), `notifications/message`,
  `notifications/resources/updated`, `notifications/resources/list_changed`,
  `notifications/prompts/list_changed`. On `notifications/tools/list_changed` the gateway reloads
  that upstream's tools and tells the client.
- **Server→client requests** from upstreams (`sampling/createMessage`, `elicitation/create`,
  `roots/list`, `ping`) are relayed to the client with a fresh id and the response is relayed back.
  If the client lacks the capability the upstream gets an error. Sampling is policy-gated; a
  denial returns an error to the upstream.
- **Resources & prompts** are proxied: `resources/list`, `resources/templates/list`,
  `resources/read`, `resources/subscribe`/`unsubscribe`, `prompts/list`, `prompts/get`,
  `completion/complete`, and `logging/setLevel` (sent to every upstream). Prompt names are
  namespaced `<upstream>__<name>`; resource URIs are kept and reads are routed to the upstream that
  listed the URI (falling back to each upstream that offers resources). List calls paginate across
  upstreams with opaque composite cursors.
- **Audit**: every gated call (tool calls, `resources/read`, `prompts/get`, sampling) is recorded
  with target `mcp:<tool>[:provider]` and `args_hash` (SHA-256 of the raw arguments JSON),
  `session` (`stdio` or `http:<session-id prefix>`), `rule` (the matched policy rule, e.g.
  `tool=fs__write_file args[path]=/workspace/** -> allow`) and `source` (who decided: `policy`,
  `session-grant`, `elicitation`, `approve`, `approval-timeout`, `builtin`). Arguments themselves
  are never logged.

## Upstream lifecycle and status

If an upstream exits (or an HTTP upstream loses its session), every pending call to it fails
immediately. Unless `--no-restart` is set the gateway restarts it with exponential backoff
(1s, 2s, 4s … max 30s), re-initializes it, reloads its tools and sends `tools/list_changed`.
After 5 consecutive failures it is marked `down`.

Each running gateway writes `<nexus home>/mcp/<pid>.json` every 10 seconds (removed on clean
exit). Inspect it with:

```console
$ nexus-cli mcp status
gateway pid 41237 (v0.9.0) running, up 12m3s
  cwd:      /home/me/repo
  policy:   /home/me/repo/nexus.yaml
  sessions: 1
  UPSTREAM  TRANSPORT  STATE  TOOLS  RESTARTS  SINCE  LAST ERROR
  fs        stdio      up     11     0         12m3s
$ nexus-cli mcp status --json
```

Files whose process no longer exists (left by a crash) are deleted by `mcp status`; files of a
live process that stopped refreshing them for 30s are reported as stale.

## Serving over Streamable HTTP

```bash
nexus-cli mcp serve --http 127.0.0.1:8765
# [nexus-mcp] bearer token (also in ~/.nexus/mcp/http.token): 3f9c…
# [nexus-mcp] MCP endpoint: http://127.0.0.1:8765/mcp
```

- One endpoint, `/mcp`: `POST` for JSON-RPC (a JSON response, or an SSE stream when the gateway has
  to send requests/notifications during the call, such as elicitation or progress), `GET` for the
  server→client SSE stream, `DELETE` to end the session.
- Sessions are identified by a random `Mcp-Session-Id` assigned on `initialize`. Each session has
  its own client capabilities (e.g. elicitation); upstreams and the policy engine are shared.
- Every request needs `Authorization: Bearer <token>`.
- DNS-rebinding protection: the `Host` header must be a loopback name (or one passed with
  `--http-allowed-host`), and browser `Origin`s other than loopback are rejected.
- Bind a loopback address. Binding anything else prints a warning.

## Why a hand-rolled JSON-RPC layer?

The gateway deliberately does not use an MCP SDK. A transparent gateway must forward messages it
does not understand: new methods, `_meta` fields, and new notification types. It also has to
rewrite ids and progress tokens while keeping every other byte intact. SDKs decode into typed
structs and drop or reject unknown content, and they hide the id/transport plumbing a proxy needs to
control. The JSON-RPC envelope is small, so owning it costs little and keeps forwarding lossless.

## Known limitations

- Taint and session grants are tracked per agent identity (`agent-id|act-as`), so all HTTP
  sessions of one gateway share them.
- The HTTP `GET` stream does not replay missed events on `Last-Event-ID`; as a client of HTTP
  upstreams, the gateway does send `Last-Event-ID` when it reconnects.
- Progress notifications that an HTTP upstream sends on its GET stream after the call has returned
  are dropped.
- The gateway offers sampling, elicitation and roots to upstreams; requests that the current client
  cannot serve get an error.
