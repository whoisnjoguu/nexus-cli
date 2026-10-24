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
- **One-command gating** — `nexus-cli run -- <agent>` puts any CLI agent or tool behind the gate: proxy, token, and CA trust are wired into its environment automatically.
- **HTTPS interception** — with a local CA (`nexus-cli ca init`), path/method rules, `one_time`, taints, and `inject` apply to HTTPS too; pinned hosts can be passed through.
- **Approve from anywhere** — answer prompts in the proxy's terminal, from another one with `nexus-cli approve`, or in a local web UI (`nexus-cli approve --web`), with desktop notifications when a request is waiting.
- **Plug-in anywhere** — HTTP forward proxy, MCP gateway over stdio or Streamable HTTP (aggregates & gates upstream MCP servers), or embedded Go/Python SDK.

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

Put any agent behind the gate with one command — no token copying, no proxy env by hand:

```bash
nexus-cli init                                   # scaffold nexus.yaml + MCP host configs
nexus-cli ca init                                # optional: local CA so HTTPS gets per-request policy
nexus-cli run -- claude                          # or: nexus-cli run -- python agent.py, -- curl …
nexus-cli approve                                # in another terminal: answer approval prompts
```

`run` starts an in-process gated proxy, mints a token for the command, launches it with
`HTTP(S)_PROXY` (and, with a CA, `SSL_CERT_FILE` & co.) pointing at the gate, and exits with the
command's exit code. Optionally log in first so calls are attributed to a verified human:

```bash
nexus-cli login --provider slack                 # authenticate via the nexus-framework Gateway
nexus-cli doctor                                 # diagnose the local setup
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
  passthrough: # HTTPS hosts tunnelled without interception (cert-pinned clients)
    - "*.pinned.example.com"

escalate_when_tainted: true # tainted session → egress to non-allowlisted host requires approval
default_action: deny

tools:
  - match:
      { method: GET, host: "api.internal.company.com", path: "/v1/claims/**" }
    scope: claims:read
    action: allow
    taints: ["db:read"] # stamps the session as having touched sensitive data

  - match: { method: POST, path: "/v1/refunds/**" }
    scope: refund:write
    action: allow
    one_time: true # allowed once per session, then denied (survives restarts)

  - match: { method: POST, path: "/v1/payouts/**" }
    scope: payout:write
    action: hitl

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

The full reference — every field, matching semantics (including MCP tool arguments), evaluation
order, taints, `one_time`, session grants, providers and egress — is in [docs/policy.md](docs/policy.md).

### Which file is the policy?

Every command resolves the policy the same way: `--policy` (when given) → `$NEXUS_POLICY` →
`$NEXUS_HOME/policy.yaml` (if it exists; `~/.nexus/policy.yaml` by default) → `./nexus.yaml`.

### Validation and `policy lint`

Policy files are parsed strictly: an unknown key anywhere (including the `mcp:` and `audit:`
sections) is an error with its line number, and so are unknown actions, malformed globs, unknown
HTTP methods, `one_time` on a non-`allow` rule, `inject: true` without a `host`, empty taints and
duplicate providers. `dev`, `run`, `mcp serve` and `policy test` refuse to load a file with errors.
Warnings flag rules that load but probably don't do what you meant: never-matching or
unreachable (shadowed) rules, `tool: "*"` / `host: "*"` allows, substring globs like `*get*`.

```bash
nexus-cli policy lint                    # human-readable; exit 1 on errors
nexus-cli policy lint --json             # machine-readable
nexus-cli policy lint --strict-warnings  # exit 1 on warnings too (CI)
# error tools[2].action: unknown action "alow" (want allow|deny|hitl)
```

`nexus-cli doctor` shows the error and warning counts.

### Hot reload

`dev`, `run` and `mcp serve` re-read the policy when it changes (polled every second by mtime,
size and SHA-256; `SIGHUP` forces a reload for `dev` and `mcp serve`). A file that fails to load
is rejected and the current policy stays in force:

```text
[nexus] policy reloaded from nexus.yaml (sha256:3f2a9c1b7d4e)
[nexus] policy reload failed: nexus.yaml: line 7: unknown field "acton" in a tools rule (keeping the current policy)
```

Every attempt is audited as tool `policy/reload` (`allow`/`deny`, target `path#sha256:<12 hex>`).
Reloads keep taints and consumed `one_time` rules and clear "approve for this session" grants.
`egress.passthrough`, `mcp:` and `audit:` changes need a restart. `--no-reload` disables it.
Writes by nexus-cli itself (`policy edit`, "always allow" approvals) are atomic, so a reload never
sees a half-written file.

### Protecting the policy from the agent

An agent that can edit its own policy isn't gated. Three layers:

- **Built-in guard** (always on, can't be overridden by rules, grants or reloads): a tool call
  whose arguments contain — anywhere, nested — a path inside the active policy file, the nexus home
  (`~/.nexus`: keys, pin, state), the audit log directory or the pin file is denied with reason
  `protected nexus file`. Relative paths (against the working directory), `..`, `~`, `file://` and
  symlinks are resolved first; command strings like `sed -i … nexus.yaml` are split into words.
  HTTP proxy requests are unaffected.
- **Move it out of the workspace**: `dev`/`run` warn when the policy is inside the current
  directory. `nexus-cli policy protect` moves it to `$NEXUS_HOME/policy.yaml` (mode 0600), which
  then takes precedence over `./nexus.yaml` (`--keep` copies instead).
- **Pin it**: `nexus-cli policy pin` records the file's SHA-256 in `$NEXUS_HOME/policy.pin`. While
  pinned, `dev`/`run`/`mcp serve` refuse to start with — and hot reload refuses to load — a policy
  whose hash differs (audited as `policy/pin`), until you review it and run `policy pin` again or
  start with `--accept-policy-change`. Changes made through nexus-cli re-pin automatically.

```bash
nexus-cli policy protect      # → /home/you/.nexus/policy.yaml
nexus-cli policy pin          # pinned /home/you/.nexus/policy.yaml sha256:… → ~/.nexus/policy.pin
```

### Persistent session state

Single-use token ids, consumed `one_time` rules and session taints are stored under
`$NEXUS_HOME/state/` (`jti.json`, `sessions.json`; dir 0700, files 0600, written atomically under a
cross-process lock), so restarting `dev`/`run` doesn't make a spent token or a `one_time` rule
usable again, and concurrent nexus-cli processes share them. Entries expire with the token / after
the 12 h session idle TTL. `--ephemeral-state` keeps everything in memory. A corrupt state file is
logged, moved aside to `*.corrupt` and treated as empty — a deliberate fail-open trade-off so a
damaged file can't brick the gate; the replay guard fails closed on I/O errors.

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
nexus-cli identity mint --agent-id claims-processor-v1 --scopes "db:read,payout:write" --ttl 900
nexus-cli identity mint -a agent-x -s db:read -q              # print only the token (for scripts)
nexus-cli identity mint -a agent-x -s db:read --single-use    # one request, then rejected
```

`act_as` binds to your logged-in principal and requested scopes are **capped by your ceiling**.
Tokens default to a 900s lifetime and are **reusable until they expire** (an agent makes many
requests with one token); `--single-use` tokens — or any token on a `dev --single-use` proxy — are
rejected on reuse via their unique `jti`. The token also carries the broker `connection_id` so the
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
nexus-cli keys jwks    # prints the current + retired Ed25519 public keys (with `kid`) as a JWKS
```

### Signing key management

The signing key lives in the OS keychain when one is available (`NEXUS_KEY_BACKEND=auto`, the
default), otherwise in `$NEXUS_HOME/ed25519.key` (0600). Force a backend with
`NEXUS_KEY_BACKEND=keychain|file`.

```bash
nexus-cli keys show                     # kid, backend, public key, location
nexus-cli keys rotate                   # new key; old one stays valid for verification
nexus-cli keys migrate --to keychain    # move a file key into the OS keychain
nexus-cli keys prune --older-than 720h  # drop long-retired keys
```

See [docs/keys.md](docs/keys.md) for the threat model and details.

## Gate a command: `nexus-cli run`

```bash
nexus-cli run -- <command> [args...]
nexus-cli run --policy ./nexus.yaml --agent-id my-agent -- python agent.py
nexus-cli run --scopes repo:read --ttl 1h -- codex
nexus-cli run --attach 127.0.0.1:8075 -- node agent.js          # reuse a running `nexus-cli dev`
eval "$(nexus-cli run --attach 127.0.0.1:8075 --print-env)"      # gate the current shell instead
```

What `run` does:

- **Proxy** — starts an in-process proxy on `127.0.0.1:<random>` with auth required (or, with
  `--attach host:port`, verifies a running `nexus-cli dev` via its health endpoint; that proxy must use
  the same signing key, i.e. the same `--key`).
- **Token** — mints a dual-actor token for the command: `sub` = `--agent-id` (default: the command's
  base name), `act_as` = your logged-in principal, else `--user-id`, else `<os user>@<hostname>`
  (with a warning that attribution is unverified). Scopes default to every `scope:` required by the
  policy, capped by your login ceiling; the token lives for `--ttl` (default 12h = max run duration).
- **Environment** — the child inherits your environment plus `HTTP_PROXY`, `HTTPS_PROXY`,
  `http_proxy`, `https_proxy`, `NEXUS_PROXY_URL` = `http://nexus:<token>@127.0.0.1:<port>`,
  `NO_PROXY`/`no_proxy` (`--no-proxy`, default `localhost,127.0.0.1,::1`), `NODE_USE_ENV_PROXY=1`,
  and `NEXUS_RUN=1`. With HTTPS interception on, the CA bundle (system roots + nexus CA) is exported
  as `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`,
  `PIP_CERT`, `CARGO_HTTP_CAINFO`, `DENO_CERT`, `HEX_CACERTS_PATH`, plus `NODE_EXTRA_CA_CERTS` = the
  nexus CA certificate.
- **Approvals** — the command owns the terminal, so `run` never draws a prompt: it prints a one-line
  notice and you answer with `nexus-cli approve` from another terminal (`--approval-timeout`, default
  2m, then the call is denied).
- **Exit** — Ctrl-C goes to the command (nexus waits for it), SIGTERM is relayed, and `run` exits with
  the command's exit code. Every decision is audited (`--no-audit` to disable).

Other flags: `--strict` (approve every call), `--inject` (broker credentials for `inject: true`
rules), `--mitm auto|on|off` (default `auto`: intercept if a CA exists; `on` creates one), `--key`.
`run` refuses to nest inside another `run` (`NEXUS_RUN=1`) unless `--attach` is used, and
`--print-env` requires `--attach` (an in-process proxy stops when `run` exits).

## Run the local zero-trust proxy

```bash
nexus-cli dev --port 8075                 # policy-enforced; require-auth ON by default
nexus-cli dev --listen 127.0.0.1:9000     # explicit bind address (non-loopback prints a warning)
nexus-cli dev --strict                    # HITL on every call, including ones the policy allows
nexus-cli dev --require-auth=false        # disable token requirement (demos only)
nexus-cli dev --policy ./nexus.yaml       # explicit policy path
nexus-cli dev --inject                    # inject broker credentials for inject: rules
nexus-cli dev --single-use                # reject any token reuse
nexus-cli dev --mitm on                   # HTTPS interception: auto (default) | on | off
nexus-cli dev --approval-timeout 2m       # how long a call waits for a human (default 60s)
nexus-cli dev --no-audit                  # disable the audit log
nexus-cli dev --no-reload                 # don't hot-reload the policy
nexus-cli dev --ephemeral-state           # keep replay/one_time/taint state in memory only
nexus-cli dev --accept-policy-change      # accept (and re-pin) a policy that differs from its pin
```

- Inbound `X-Nexus-*` headers are **always stripped** — identity comes only from a verified token.
- **Forward proxy**: point an agent at it via `HTTP_PROXY` / `HTTPS_PROXY`; approved requests are
  forwarded with dual-actor attribution headers (`X-Nexus-Agent-ID`, `X-Nexus-Act-As`) injected and
  the proxy credentials removed.
- **Authentication**: put the token in the proxy URL — `http://nexus:<TOKEN>@127.0.0.1:8075` sends
  `Proxy-Authorization: Basic base64(nexus:<TOKEN>)`, which every proxy-aware client supports (the
  username is ignored). `Proxy-Authorization: Bearer`, `Authorization: Bearer`, and `X-Nexus-Token`
  are also accepted for plain HTTP. A `CONNECT` without a valid token gets `407` before any TLS.
- **Approvals**: prompts appear in the `dev` terminal (when it is interactive) **and** can be answered
  from any other terminal with `nexus-cli approve`; the first answer wins. With no answer within
  `--approval-timeout` the call is denied (fail closed).
- **Health**: `GET http://127.0.0.1:8075/_nexus/health` (no token needed) returns
  `{"status":"ok","service":"nexus-cli","mitm":"on|off",…}` plus `ca_fingerprint` when
  intercepting and `token: valid|invalid` when a token is presented.

```bash
TOKEN=$(nexus-cli identity mint -a agent-x -s db:read -q)
curl -x "http://nexus:$TOKEN@127.0.0.1:8075" http://api.internal.company.com/v1/claims/1
```

### Run as a service

Keep the proxy running in the background (and across logins) as a per-user service: a systemd
**user** unit on Linux, a launchd agent on macOS, or a logon Scheduled Task on Windows. No root
needed.

```bash
nexus-cli service install --policy ./nexus.yaml   # --dry-run prints the unit/plist/command only
nexus-cli service status                          # platform state + /_nexus/health + control entry
nexus-cli service logs -f                         # journalctl / launchd log / service.log
nexus-cli run --attach 127.0.0.1:8075 -- <cmd>    # gate commands through the service's proxy
nexus-cli approve                                 # answer approval prompts (no TTY under a service)
```

The service runs `dev` with an absolute policy path and the same `NEXUS_HOME`, so `run --attach`,
`approve` and `doctor` find it — **`NEXUS_HOME` must match** in your shell. See
[docs/service.md](docs/service.md) for flags, hardening, linger and Windows limitations.

### HTTPS interception

Without a CA, HTTPS is tunnelled via `CONNECT` and gated on the **host** only. Create a local CA and
nexus terminates TLS for each `CONNECT` with a per-host certificate, so every request inside the
tunnel — keep-alive, chunked bodies, websocket upgrades — goes through the same pipeline as plain
HTTP: path/method rules, scopes, `one_time`, taints, HITL, `inject: true`, and per-request audit.

```bash
nexus-cli ca init          # create the CA under ~/.nexus/ca (or $NEXUS_HOME/ca)
nexus-cli ca path          # CA certificate path (--bundle: write system roots + CA bundle)
nexus-cli ca fingerprint   # SHA-256 fingerprint
nexus-cli ca install       # show (--run: execute) the commands that trust it OS-wide
nexus-cli ca uninstall     # show (--run: execute) the commands that remove it
```

- `dev --mitm auto` (default) intercepts when a CA exists; `on` creates one; `off` disables it.
- Clients must trust the CA: `nexus-cli run` sets the CA environment variables automatically, or
  install it system-wide with `nexus-cli ca install`. A client that rejects the certificate is
  audited as a deny and nexus prints a hint (`client rejected nexus CA for <host>; …`).
- The authenticated identity, replay and single-use checks happen once on the `CONNECT` and apply to
  every request on that tunnel. A request whose `Host` differs from the `CONNECT` host is rejected
  (domain-fronting guard). The client's own `Authorization` header inside the tunnel is forwarded.
- Hosts listed under `egress.passthrough` (same `*.example.com` patterns as `egress.allow`) are
  tunnelled raw and gated per host — use it for certificate-pinned clients.
- Upstream TLS is always verified against the system roots; nexus speaks HTTP/1.1 upstream.

## Approvals

Calls that hit a `hitl` rule wait for a human (fail closed after `--approval-timeout`). Answer them
wherever is convenient — the first answer wins:

```bash
nexus-cli approve                     # interactive watcher across all local gateways (bell on new requests; -q to silence)
nexus-cli approve --list              # print pending requests
nexus-cli approve <id> --decision once   # once | session | always | deny
nexus-cli approve --web               # open the local approvals web UI (one-time login link)
nexus-cli approve --web --no-open     # just print the link; --pid <pid> picks a gateway
```

The web UI is served by the gateway's loopback control API: it lists pending requests (agent,
act-as, tool, target, reason, age, countdown to auto-deny), the last 20 decisions, and updates live.
Browsers sign in with a single-use 60s link and get an HttpOnly, SameSite=Strict session cookie; every
cookie request is Host-, Origin- and CSRF-checked. `dev`, `run` and `mcp serve` also show a desktop
notification when a request starts waiting (`--notify auto|off`, or `NEXUS_NOTIFY=off`). See
[docs/approvals.md](docs/approvals.md).

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

- **Argument-aware rules** — match tool-call arguments (`match: {tool: "fs__write_file", args: {path: "/workspace/*"}}`);
  a `url`/`uri`/`endpoint` argument is also checked against the egress allowlist.
- **Full passthrough** — resources, prompts, completion, logging, progress, cancellation and
  `list_changed` notifications; upstream sampling (policy-gated), elicitation and roots requests reach the client.
- **Concurrent and supervised** — calls run in parallel with a per-call timeout (`--call-timeout`);
  crashed upstreams fail their pending calls and restart with backoff (`no_restart: true` to opt out).
- **stdio or Streamable HTTP** upstreams (`url:` + `headers:` with `${ENV}` expansion), and
  `--http 127.0.0.1:8765` to serve the gateway itself over HTTP with a bearer token.
- **Approvals** — HITL calls use MCP elicitation when the client supports it, and are always
  answerable from another terminal with `nexus-cli approve`.
- `nexus-cli mcp status` shows running gateways and upstream health (`doctor` flags down upstreams).

See [docs/mcp.md](docs/mcp.md) for the full reference.

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

Every decision is appended to a hash-chained JSONL log at `$NEXUS_HOME/audit.jsonl` (default
`~/.nexus/audit.jsonl`). It is fsync'd, rotated at 10 MiB, and safe for concurrent writers
(`dev`, `run` and `mcp serve` at once).

```bash
nexus-cli audit tail -n 20 -f --agent my-agent   # recent decisions, then follow
nexus-cli audit verify                           # chain + signatures (detects edits/deletions)
nexus-cli audit head                             # record this hash somewhere off-machine…
nexus-cli audit verify --anchor <hash>           # …and later prove history up to it is intact
nexus-cli audit export --format csv --since 24h  # for spreadsheets / SIEM import
```

Configure signing and off-box sinks in `nexus.yaml` (`${ENV}` is expanded in URLs and headers):

```yaml
audit:
  sign: true # Ed25519-sign every entry ($NEXUS_HOME/audit.key / audit.pub)
  sinks:
    - type: webhook
      url: https://siem.example.com/ingest
      headers: { Authorization: "Bearer ${SIEM_TOKEN}" }
    - type: syslog
      network: udp
      addr: logs.example.com:514
```

A process running as your user can rewrite a local log; anchors and remote sinks are what make
that detectable. See [docs/audit.md](docs/audit.md).

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
one-liner above. For HTTP tool traffic, route it through a running `nexus-cli dev`:

```bash
eval "$(nexus-cli run --attach 127.0.0.1:8075 --print-env)"   # sets HTTP(S)_PROXY with a token + CA vars
```

## Commands

| Command                                  | Description                                                                          |
| ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `nexus-cli init`                         | Scaffold `nexus.yaml` + MCP host configs                                             |
| `nexus-cli login`                        | Authenticate the human principal via the Gateway                                     |
| `nexus-cli connect`                      | Connect an additional provider to your session                                       |
| `nexus-cli connections`                  | List provider connections + live status                                              |
| `nexus-cli providers`                    | List providers available on the Gateway                                              |
| `nexus-cli whoami`                       | Show the logged-in principal                                                         |
| `nexus-cli logout`                       | Clear the cached session                                                             |
| `nexus-cli identity mint`                | Mint a short-lived dual-actor JWT for an agent session                               |
| `nexus-cli run -- <cmd>`                 | Run a command behind the gate (proxy + token + CA env)                               |
| `nexus-cli dev`                          | Start the local zero-trust proxy with policy + HITL                                  |
| `nexus-cli approve`                      | Answer pending approvals from another terminal (`--list`, `--web` UI, `--pid`, `-q`) |
| `nexus-cli service install`              | Run `dev` as a per-user background service (`--dry-run`)                             |
| `nexus-cli service uninstall`            | Stop, disable and remove the service                                                 |
| `nexus-cli service start\|stop\|restart` | Control the installed service                                                        |
| `nexus-cli service status`               | Service state, health and control entry (`--json`)                                   |
| `nexus-cli service logs`                 | Show service logs (`-f` to follow, `-n` lines)                                       |
| `nexus-cli ca init`                      | Create the local CA for HTTPS interception                                           |
| `nexus-cli ca path`                      | Print the CA path (`--bundle`: write the CA bundle)                                  |
| `nexus-cli ca fingerprint`               | Print the CA certificate's SHA-256 fingerprint                                       |
| `nexus-cli ca install`                   | Trust the CA in the OS store (`uninstall` to remove)                                 |
| `nexus-cli mcp serve`                    | Serve / aggregate MCP tool servers behind the policy                                 |
| `nexus-cli mcp status`                   | Show running MCP gateways and upstream health                                        |
| `nexus-cli policy edit`                  | Interactive TUI policy editor (writes `nexus.yaml`)                                  |
| `nexus-cli policy test`                  | Dry-run a tool call against the policy                                               |
| `nexus-cli policy lint`                  | Validate the policy (`--json`, `--strict-warnings`)                                  |
| `nexus-cli policy protect`               | Move the policy to `$NEXUS_HOME/policy.yaml` (0600)                                  |
| `nexus-cli policy pin`                   | Pin the policy's SHA-256; refuse unreviewed changes                                  |
| `nexus-cli audit tail`                   | Show recent decisions (`-f` to follow, filters)                                      |
| `nexus-cli audit verify`                 | Verify the audit hash chain, signatures and anchor                                   |
| `nexus-cli audit head`                   | Print the chain head to store as an off-machine anchor                               |
| `nexus-cli audit export`                 | Export decisions as JSONL or CSV                                                     |
| `nexus-cli audit keygen`                 | Create the audit signing key pair                                                    |
| `nexus-cli keys jwks`                    | Print the public verification keys as a JWKS                                         |
| `nexus-cli keys show`                    | Show signing key id, backend and location                                            |
| `nexus-cli keys rotate`                  | Rotate the signing key (`migrate`, `prune` also exist)                               |
| `nexus-cli doctor`                       | Diagnose the local setup                                                             |
| `nexus-cli version`                      | Print the version, commit, and platform                                              |

## Project Layout

```text
nexus-cli/
├── cmd/                 # Cobra command tree
├── external/            # embedded init scaffolds (nexus.yaml, mcp.json templates)
├── internal/
│   ├── atomicfile/      # temp+rename file writes (policy, pin, state)
│   ├── fslock/          # cross-process advisory file locks
│   └── tui/             # Bubble Tea policy editor (nexus-cli policy edit)
├── packaging/npm/       # npx launcher (@whoisnjoguu/nexus-cli)
├── pkg/
│   ├── audit/           # hash-chained, tamper-evident decision log
│   ├── credential/      # broker credential resolver (nexus-framework SDK)
│   ├── ca/              # local CA + per-host leaf certificates for HTTPS interception
│   ├── control/         # loopback control API + approvals web UI used by `nexus-cli approve`
│   ├── hitl/            # approval broker, terminal prompt, first-answer-wins fan-out
│   ├── jwt/             # Ed25519 signing, verification, keystore, replay guard, JWKS
│   ├── mcp/             # MCP stdio server + upstream gateway + broker-access tools
│   ├── notify/          # desktop notifications for pending approvals
│   ├── policy/          # policy engine, validation, hot reload, guard, pinning, session state
│   ├── state/           # expiring JSON state store under $NEXUS_HOME/state
│   ├── principal/       # human identity + multi-provider connections via the Gateway
│   ├── proxy/           # forward proxy, auth, CONNECT tunnelling + TLS interception
│   ├── service/         # per-user service managers (systemd, launchd, Task Scheduler)
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

- Tokens are signed with a persistent Ed25519 key stored in the OS keychain when available, else
  `~/.nexus/ed25519.key` (0600), shared by `identity mint`, the proxy verifier, and the MCP server.
  Override with `--key` / `NEXUS_KEY_BACKEND`; set `NEXUS_HOME` to relocate `~/.nexus`.
- With `--require-auth`, downstream attribution is derived from verified JWT claims, not
  client-supplied headers. Tokens are validated for signature, issuer, audience, and expiry.
- MCP `--strict` fails closed: tool calls are denied unless a human explicitly approves via
  elicitation.
- HTTPS `CONNECT` traffic is inspected per request only when HTTPS interception is on (a CA
  exists, see `nexus-cli ca init`) and the host is not in `egress.passthrough`; otherwise it is
  tunnelled and gated on host only.
- The CA private key (`~/.nexus/ca`, 0600) can mint certificates for any host: anyone who can read
  it can intercept TLS for clients that trust the CA. `nexus-cli ca uninstall` removes OS trust.
