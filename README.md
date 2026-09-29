<div align="center">

# nexus-cli

**Zero-trust security sidecar, identity broker, and MCP gateway for autonomous coding agents.**

[![CI](https://github.com/whoisnjoguu/nexus-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/whoisnjoguu/nexus-cli/actions/workflows/ci.yml)
[![Release](https://github.com/whoisnjoguu/nexus-cli/actions/workflows/release.yml/badge.svg)](https://github.com/whoisnjoguu/nexus-cli/actions/workflows/release.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/whoisnjoguu/nexus-cli.svg)](https://pkg.go.dev/github.com/whoisnjoguu/nexus-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/whoisnjoguu/nexus-cli)](https://goreportcard.com/report/github.com/whoisnjoguu/nexus-cli)
[![Latest Release](https://img.shields.io/github/v/release/whoisnjoguu/nexus-cli?sort=semver)](https://github.com/whoisnjoguu/nexus-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/whoisnjoguu/nexus-cli)](go.mod)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

[Why](#why) · [Quick start](#quick-start) · [Policy](#policy-nexusyaml) · [Identity](#identity) · [Proxy](#run-the-local-zero-trust-proxy) · [MCP gateway](#mcp-gateway) · [SDKs](#embed-in-your-agent-sdks) · [IDE integration](#ide-integration)

</div>

---

`nexus-cli` is an agent-agnostic local proxy and gateway that sits between your AI agent (Claude
Code, GitHub Copilot, or any local agent loop) and the tools, APIs, and cloud services it calls.
Instead of agents holding static credentials and executing tools directly, every tool call is
routed through `nexus-cli`, which enforces a **declarative least-privilege policy**, cryptographically
verifiable **dual-actor identity** (Agent + Human), human-in-the-loop approvals, and a
**tamper-evident audit log**.

```text
┌─────────────────────────┐    1. Request Tool Token    ┌────────────────────────┐
│  Claude Code / Copilot  ├────────────────────────────►│                        │
│   / Local Agent Loop    │                             │       nexus-cli        │
│    (Python/TS/Go)       │◄────────────────────────────┤  (Local Security CLI)  │
└────────┬────────────────┘   2. Micro-JWT Issued       └───────────┬────────────┘
         │                   (sub:agent, act_as:human)               │
         │ 3. Intercepted Tool Request                               │
         ▼                                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          nexus-cli Local Proxy / MCP                              │
│  [A] Policy Engine        least-privilege scopes, egress allowlist, taint         │
│  [B] Dual-Actor Auth      verifies micro-JWT signature, TTL, single-use (jti)     │
│  [C] HITL Prompt          intercepts high-risk / destructive calls                │
│  [D] Audit Log            hash-chained, tamper-evident decision record            │
└───────────────────────────────────────────┬─────────────────────────────────────┘
                                            │ 4. Proxied Call + Dual-Actor Claims
                                            ▼
                                 ┌──────────────────────┐
                                 │ External APIs / MCP  │
                                 │ Databases / Cloud    │
                                 └──────────────────────┘
```

## Why

`nexus-cli` targets two concrete risks in agentic workflows:

- **Tool Chain Exposure** — an agent chaining a harmless read (`read_file`) into a powerful egress
  call can be manipulated via prompt injection to exfiltrate data. `nexus-cli` enforces per-tool
  **scopes**, an **egress allowlist**, and **session taint tracking** that escalates any egress to a
  non-allowlisted host to a human decision once the session has touched sensitive data — catching
  read-then-exfiltrate chains individual controls miss.
- **Identity Fluidity & Attribution Gaps** — shared static keys mask autonomous execution behind a
  human persona. `nexus-cli` replaces them with short-lived Ed25519 **dual-actor tokens** binding the
  **Agent** (`sub`) to a **Human Principal** (`act_as`). Authentication is brokered by the
  [nexus-framework](https://github.com/Prescott-Data/nexus-framework) Gateway — nexus-cli holds no
  OAuth code and never sees a raw secret — and the human's scope ceiling caps what the agent can
  request. Every action lands in a hash-chained audit log.

## Features

- **Least-privilege policy** — declarative `nexus.yaml` with per-tool scopes, egress allowlist, and `allow` / `deny` / `hitl` decisions.
- **Safe-tier defaults (no approval fatigue)** — read-only tools and GETs run without prompting, the destructive tail (`execute_shell`, …) is denied, and only the ambiguous middle asks.
- **Approve once, session, or always** — a HITL prompt offers _once_, _this session_, or _always_ (saved to `nexus.yaml`), so you approve intent — not every tool call.
- **Tool-chain taint tracking** — escalates egress to non-allowlisted hosts once a session touches sensitive data (catches read-then-exfiltrate).
- **Dual-actor identity** — short-lived Ed25519 tokens binding agent (`sub`) to a verified human (`act_as`) with `jti` replay protection and a JWKS endpoint for downstream verification.
- **Secretless egress** — brokered credentials injected at the edge; the agent never holds a durable secret.
- **Agent-requested access** — MCP tools let an agent request provider access; the human approves consent and the token stays in the broker (`get_credential` is deny-by-default).
- **TUI policy editor** — `nexus-cli policy edit` manages providers, scopes, tools, egress, and defaults; writes `nexus.yaml` for you.
- **Tamper-evident audit** — hash-chained JSONL log with `audit verify`.
- **Plug-in anywhere** — HTTP forward proxy, MCP stdio gateway (aggregates & gates upstream MCP servers), or embedded Go/Python SDK.

## Install

**Zero-install via npx** — great for MCP hosts; downloads the right binary on first run:

```bash
npx -y @whoisnjoguu/nexus-cli mcp serve --strict
npx -y @whoisnjoguu/nexus-cli version
```

**Prebuilt binary** — installs the latest release for your OS/arch:

```bash
curl -fsSL https://raw.githubusercontent.com/whoisnjoguu/nexus-cli/master/install.sh | sh
NEXUS_VERSION=v0.2.0 curl -fsSL https://raw.githubusercontent.com/whoisnjoguu/nexus-cli/master/install.sh | sh   # pin a version
```

**Homebrew** — `brew install whoisnjoguu/tap/nexus-cli` · **Go** — `go install github.com/whoisnjoguu/nexus-cli@latest`

**From source:**

```bash
git clone https://github.com/whoisnjoguu/nexus-cli.git
cd nexus-cli
make build          # produces ./nexus-cli
make install        # or install to $GOBIN / $GOPATH/bin
```

Requires Go 1.25+. Prebuilt binaries for Linux, macOS, and Windows (amd64 + arm64), a container
image, and a Homebrew formula are published on each release via `goreleaser`. Check your build with
`nexus-cli version`.

## Quick start

```bash
nexus-cli init                                          # scaffold nexus.yaml + MCP host configs
nexus-cli login --provider slack                        # authenticate via the nexus-framework Gateway
nexus-cli dev                                           # start the gated proxy (auth on by default)
nexus-cli doctor                                        # diagnose the local setup
```

> Login is brokered by a running [nexus-framework](https://github.com/Prescott-Data/nexus-framework)
> Gateway (`make up` in that repo; default `http://localhost:8090`, override with `--gateway` or
> `NEXUS_GATEWAY_URL`). Register your providers there once; nexus-cli never touches OAuth directly.

## Policy (`nexus.yaml`)

The policy turns the token's scopes into an actual privilege ceiling. Decisions are `allow`, `deny`,
or `hitl` (human approval). No matching rule → `default_action` (deny).

```yaml
agent: claims-processor-v1

egress:
  allow:
    - "*.github.com"
    - "api.internal.company.com"

escalate_when_tainted: true # tainted session → egress to non-allowlisted host requires approval
default_action: deny

tools:
  - match:
      { method: GET, host: "api.internal.company.com", path: "/v1/claims/**" }
    scope: claims:read
    action: allow
    taints: ["db:read"] # stamps the session as having touched sensitive data

  - match: { method: POST, path: "/v1/payouts/**" }
    scope: payout:write
    action: hitl
    one_time: true # authorization consumed after a single use per session

  - match: { tool: execute_shell }
    action: deny
```

Dry-run any call without executing it:

```bash
nexus-cli policy test --method POST --url http://api.internal.company.com/v1/payouts/execute --scopes payout:write
nexus-cli policy test --tool request_access --provider github    # test provider access rules
# Decision: HITL
```

### Edit the policy interactively (no YAML by hand)

`nexus-cli policy edit` opens a Bubble Tea TUI to manage the whole policy — provider access +
scopes, MCP tool rules, the egress allowlist, and defaults — and writes `nexus.yaml` on save.

```bash
nexus-cli policy edit --gateway https://your-gateway.example.com
```

```text
┌ nexus · policy editor ─────────────────────────  nexus.yaml ● unsaved ┐
│ ▸ Providers   │  github               [ ALLOW ]  cred [ DENY ]        │
│   Tools       │    ▣ repo  ▣ read:user  ▢ delete_repo                 │
│   Egress      │  google-drive         [ HITL  ]  cred [ DENY ]        │
│   Defaults    │    ▣ openid ▣ email ▢ drive                           │
├───────────────────────────────────────────────────────────────────────┤
│ ↑↓ move · tab section · a/h/d action · space toggle · ctrl+s save · q  │
└───────────────────────────────────────────────────────────────────────┘
```

Scopes are pulled live from the Gateway's catalog, so you check real provider scopes.

## Identity

### Log in as the human principal

`act_as` comes from a verified login the agent cannot forge. Authentication is delegated to the
**nexus-framework Gateway**, which brokers OAuth 2.0 / OIDC for any provider registered with it
(GitHub, Slack, Google, your IdP). nexus-cli only learns the resulting identity and a broker
connection handle — it never holds a provider secret.

```bash
GW="https://your-gateway.example.com"   # or export NEXUS_GATEWAY_URL

nexus-cli login --provider google-drive --gateway "$GW"            # any Gateway-registered provider
nexus-cli login --provider github --gateway "$GW" --scopes db:read # --scopes = nexus ceiling to delegate
nexus-cli login --provider local  --email alice@company.com        # offline fallback (weak attribution)
nexus-cli whoami
nexus-cli logout
```

### Connect additional providers

One human can hold connections to many providers at once. Add more without re-logging-in:

```bash
nexus-cli connect --provider github --gateway "$GW"   # browser consent, stored in your session
nexus-cli connections                                 # list connections + live status
nexus-cli providers --gateway "$GW"                   # what the Gateway offers
```

Login opens your browser for consent, waits for the Gateway to activate the connection, and caches a
short-lived principal in `~/.nexus/session.json` — including the `connection_id` used later for
secretless credential injection.

### Mint a dual-actor token

```bash
nexus-cli identity mint --agent-id claims-processor-v1 --scopes "db:read,payout:write" --ttl 30
```

`act_as` binds to your logged-in principal and requested scopes are **capped by your ceiling**. The
token carries a unique `jti` for single-use / replay protection and the broker `connection_id` so the
proxy can inject upstream credentials on your behalf. The signing key is persisted to
`~/.nexus/ed25519.key` (`0600`, created on first use).

### Secretless credential injection

With a broker-backed login, the agent can hold **zero** upstream secrets. Mark a rule `inject: true`
and run the proxy with `--inject`; on an allowed request nexus fetches a short-lived credential from
the Gateway for your connection, strips any client-supplied auth, and sets `Authorization` before
forwarding to the allowlisted upstream.

```yaml
tools:
  - match: { method: GET, host: "api.github.com", path: "/**" }
    scope: gh:read
    action: allow
    inject: true
```

```bash
nexus-cli dev --inject
```

### Downstream verification (JWKS)

Services can verify nexus-issued tokens themselves instead of trusting proxy headers:

```bash
nexus-cli keys jwks    # prints the Ed25519 public key as a JSON Web Key Set
```

## Run the local zero-trust proxy

```bash
nexus-cli dev --port 8075                 # policy-enforced; require-auth ON by default
nexus-cli dev --strict                    # HITL on every call, including GET/CONNECT
nexus-cli dev --require-auth=false         # disable token requirement (demos only)
nexus-cli dev --policy ./nexus.yaml        # explicit policy path
nexus-cli dev --inject                     # inject broker credentials for inject: rules
nexus-cli dev --no-audit                   # disable the audit log
```

- Inbound `X-Nexus-*` headers are **always stripped** — identity comes only from a verified token.
- **Forward proxy**: point an agent at it via `HTTP_PROXY` / `HTTPS_PROXY`; approved requests are
  forwarded with dual-actor attribution headers injected. HTTPS is tunneled via `CONNECT` (gated on
  host). HITL prompts are serialized and **fail closed** when no interactive terminal is attached.

```bash
TOKEN=$(nexus-cli identity mint -a agent-x -s db:read -t 60 | awk '/Micro-JWT/{print $2}')
curl -x http://127.0.0.1:8075 -H "Authorization: Bearer $TOKEN" http://api.internal.company.com/v1/claims/1
```

## MCP gateway

Serve as an MCP stdio server, or aggregate and gate **other** MCP servers behind one policy.

```bash
nexus-cli mcp serve                # exposes mint_token; policy-gated tool calls
nexus-cli mcp serve --strict       # approve every tool call via MCP elicitation
```

Configure upstream servers in `nexus.yaml` and nexus spawns them, aggregates their `tools/list`
(namespaced as `name__tool`), and gates every `tools/call` through policy + HITL + audit:

```yaml
mcp:
  upstreams:
    - name: fs
      command: npx
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
    - name: gh
      command: docker
      args: ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]
```

Then a host replaces N server entries with a single `nexus-cli mcp serve`.

### Agents request provider access (secretless)

When started with a Gateway (`--gateway`, `NEXUS_GATEWAY_URL`, or your login), the MCP server exposes
broker-access tools so an agent can request credentials for a provider — but **the human approves the
OAuth consent, and the agent never sees a raw token**:

| Tool                                | What it does                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------ |
| `list_providers`                    | Providers available on the Gateway.                                                  |
| `request_access(provider, scopes?)` | Returns a consent URL for the human to approve; the agent cannot self-grant.         |
| `connection_status(provider)`       | Poll until the connection is active.                                                 |
| `get_credential(provider)`          | Returns a token — **denied by default** (secretless); only if a policy rule opts in. |

```bash
nexus-cli mcp serve --gateway https://your-gateway.example.com
```

Access per provider is governed by the `providers:` section of `nexus.yaml` (edit it with
`nexus-cli policy edit`):

```yaml
providers:
  github:
    access: allow # request_access allowed
    scopes: [repo, read:user]
  google-drive:
    access: hitl # request_access needs human approval
  # get_credential is deny-by-default everywhere unless you set `credential: hitl|allow`
```

The recommended pattern is **capability, not tokens**: let the agent act _through_ nexus (proxy
injection or a gated upstream MCP server) so the secret stays in the broker.

## Audit log

Every decision is appended to a hash-chained JSONL log at `~/.nexus/audit.jsonl`:

```bash
nexus-cli audit tail -n 20    # recent decisions
nexus-cli audit verify        # confirm the chain is intact (detects edits/deletions)
```

## Embed in your agent (SDKs)

### Go

Gate tool calls in-process — no proxy required:

```go
engine := policy.NewEngine(pol)
gate := sdk.NewLocalGate(engine, approver, auditlog)

dec, _ := gate.Authorize(ctx, sdk.ToolCall{
    SessionID: sessionID, Agent: "agent-x", ActAs: "alice@company.com",
    Method: "POST", Host: "api.internal.company.com", Path: "/v1/payouts/execute",
    Scopes: []string{"payout:write"},
})
if !dec.Allowed { return fmt.Errorf("denied: %s", dec.Reason) }
```

Or drop a gating transport into any `http.Client`:

```go
client := &http.Client{Transport: &sdk.GateTransport{Gate: gate, Tokens: src, Agent: "agent-x", ActAs: "alice@company.com"}}
```

### Python

```python
from nexus import PolicyGate, guard, DeniedError

gate = PolicyGate()   # uses ./nexus.yaml and the nexus-cli binary

@guard(gate, tool="execute_shell")
def execute_shell(cmd: str) -> str:
    ...
```

See [sdk/python/README.md](sdk/python/README.md).

## IDE Integration

**One-liners (no config file):**

```bash
# Claude Code
claude mcp add nexus -- npx -y @whoisnjoguu/nexus-cli mcp serve --strict

# VS Code / Copilot
code --add-mcp '{"name":"nexus","command":"npx","args":["-y","@whoisnjoguu/nexus-cli","mcp","serve","--strict"]}'
```

### Claude Code (MCP)

```json
// .claude/mcp.json  (generated by `nexus-cli init`)
{
  "mcpServers": {
    "nexus-security-guardrail": {
      "command": "nexus-cli",
      "args": ["mcp", "serve", "--strict"]
    }
  }
}
```

In `--strict`, tool calls surface a native approval prompt in Claude Code via MCP elicitation before
executing (approve once, for the session, or always).

### GitHub Copilot / VS Code

`nexus-cli init` writes `.vscode/mcp.json`; open it and click **Start**, or use the `code --add-mcp`
one-liner above. For HTTP tool traffic, route it through the proxy instead:

```bash
export HTTP_PROXY="http://127.0.0.1:8075"
export HTTPS_PROXY="http://127.0.0.1:8075"
```

## Commands

| Command                   | Description                                            |
| ------------------------- | ------------------------------------------------------ |
| `nexus-cli init`          | Scaffold `nexus.yaml` + MCP host configs               |
| `nexus-cli login`         | Authenticate the human principal via the Gateway       |
| `nexus-cli connect`       | Connect an additional provider to your session         |
| `nexus-cli connections`   | List provider connections + live status                |
| `nexus-cli providers`     | List providers available on the Gateway                |
| `nexus-cli whoami`        | Show the logged-in principal                           |
| `nexus-cli logout`        | Clear the cached session                               |
| `nexus-cli identity mint` | Mint a short-lived dual-actor JWT for an agent session |
| `nexus-cli dev`           | Start the local zero-trust proxy with policy + HITL    |
| `nexus-cli mcp serve`     | Serve / aggregate MCP tool servers behind the policy   |
| `nexus-cli policy edit`   | Interactive TUI policy editor (writes `nexus.yaml`)    |
| `nexus-cli policy test`   | Dry-run a tool call against the policy                 |
| `nexus-cli audit tail`    | Show recent authorization decisions                    |
| `nexus-cli audit verify`  | Verify the audit hash chain                            |
| `nexus-cli keys jwks`     | Print the public verification key as a JWKS            |
| `nexus-cli doctor`        | Diagnose the local setup                               |
| `nexus-cli version`       | Print the version, commit, and platform                |

## Project Layout

```text
nexus-cli/
├── cmd/                 # Cobra command tree
├── external/            # embedded init scaffolds (nexus.yaml, mcp.json templates)
├── internal/
│   └── tui/             # Bubble Tea policy editor (nexus-cli policy edit)
├── packaging/npm/       # npx launcher (@whoisnjoguu/nexus-cli)
├── pkg/
│   ├── audit/           # hash-chained, tamper-evident decision log
│   ├── credential/      # broker credential resolver (nexus-framework SDK)
│   ├── hitl/            # Bubbletea human-in-the-loop approval prompt
│   ├── jwt/             # Ed25519 signing, verification, keystore, replay guard, JWKS
│   ├── mcp/             # MCP stdio server + upstream gateway + broker-access tools
│   ├── policy/          # declarative least-privilege policy engine
│   ├── principal/       # human identity + multi-provider connections via the Gateway
│   ├── proxy/           # intercepting forward proxy + CONNECT tunneling + auth
│   └── sdk/             # embeddable Go gate + gating http.RoundTripper
├── sdk/python/          # Python SDK
├── Dockerfile           # distroless sidecar image
├── .goreleaser.yaml     # release / Homebrew / Docker config
├── go.mod
└── main.go
```

## Development

```bash
make build   # compile the binary
make run     # run the dev proxy
make test    # run tests
make vet     # go vet
make fmt     # gofmt
make tidy    # go mod tidy
make clean   # remove build artifacts
```

Cross-compile for all platforms (matches the release matrix — Linux, macOS, Windows × amd64/arm64):

```bash
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS="${t%/*}" GOARCH="${t#*/}" CGO_ENABLED=0 go build -o /dev/null . && echo "ok $t"
done
```

## Releasing

Releases are built by [GoReleaser](https://goreleaser.com) via GitHub Actions on any `v*` tag —
producing archives for Linux/macOS/Windows (amd64 + arm64), a GHCR container image, and (optionally)
a Homebrew formula.

```bash
git tag v0.1.0 && git push origin v0.1.0     # triggers .github/workflows/release.yml
goreleaser release --snapshot --clean         # dry-run locally (no publish)
```

Optional secrets: `HOMEBREW_TAP_TOKEN` (PAT for the tap repo; brew step is skipped if unset). GHCR
push uses the built-in `GITHUB_TOKEN`.

## Contributing

Contributions are welcome. Please:

1. Open an issue to discuss substantial changes first.
2. Keep the suite green: `make check` (gofmt + `go vet` + tests).
3. Add tests for new behavior and keep changes focused.

## Security

`nexus-cli` is a security tool; please report vulnerabilities privately via a GitHub security advisory
rather than a public issue.

## License

[MIT](LICENSE) © Alan N.

## Security Notes

- Tokens are signed with a persistent Ed25519 key at `~/.nexus/ed25519.key` (0600),
  shared by `identity mint`, the proxy verifier, and the MCP server. Override with `--key`.
- With `--require-auth`, downstream attribution is derived from verified JWT claims, not
  client-supplied headers. Tokens are validated for signature, issuer, audience, and expiry.
- MCP `--strict` fails closed: tool calls are denied unless a human explicitly approves via
  elicitation.
- HTTPS `CONNECT` traffic is tunneled, not inspected; per-request payload inspection
  applies to plain HTTP only.
