# Recipes

These are copy-pasteable setups for common agents and environments. They use only flags and config
keys that exist in nexus-cli. For third-party tools, only the minimum config is shown, together
with the file it goes in. Check that tool's own documentation for anything else.

All of these assume `nexus-cli` is on your `PATH` (see [Install](../README.md#install)) and that
you start in your project directory.

- [Start: scaffold a project](#start-scaffold-a-project)
- [Claude Code](#claude-code)
- [GitHub Copilot CLI](#github-copilot-cli)
- [VS Code (GitHub Copilot)](#vs-code-github-copilot)
- [Cursor](#cursor)
- [A Python agent with the `nexus` SDK](#a-python-agent-with-the-nexus-sdk)
- [A Go program with `sdk/go`](#a-go-program-with-sdkgo)
- [`dev` as a background service plus `run --attach`](#dev-as-a-background-service-plus-run---attach)
- [CI: an agent in GitHub Actions](#ci-an-agent-in-github-actions)

## Start: scaffold a project

```bash
nexus-cli init            # writes nexus.yaml, .claude/mcp.json, .vscode/mcp.json (skips existing files)
nexus-cli init --strict   # same, but the MCP configs run `mcp serve --strict` (approve every call)
nexus-cli init --force    # overwrite existing files
nexus-cli policy lint     # check the policy
```

The scaffolded `nexus.yaml`:

- allows read-only tools and `GET` requests;
- denies `execute_shell`;
- asks for approval for `*delete*` tools and anything unmatched (`default_action: hitl`);
- restricts other egress to `egress.allow: ["*.github.com", "api.openai.com"]`.

Add the hosts your agent really needs, for example its model API, to `egress.allow`. Otherwise
`POST` requests to them are denied, and so is every HTTPS tunnel to them when interception is off
(`CONNECT`):

```bash
nexus-cli policy test --method POST --url https://api.anthropic.com/v1/messages
# Decision: DENY  host "api.anthropic.com" not in egress allowlist
```

Answer approval prompts from a second terminal with `nexus-cli approve`, or use `--web` for the
browser UI. See [approvals.md](approvals.md).

## Claude Code

Claude Code can use nexus-cli in two independent ways. Use either one, or both.

### 1. Tool calls through the MCP gateway

Claude Code reads project MCP servers from **`.mcp.json` at the repository root**. `nexus-cli init`
writes the same `mcpServers` block to `.claude/mcp.json`. Copy it, or create `.mcp.json` yourself:

```json
{
  "mcpServers": {
    "nexus-security-guardrail": {
      "command": "nexus-cli",
      "args": ["mcp", "serve"]
    }
  }
}
```

Or register it with the Claude Code CLI:

```bash
claude mcp add nexus-security-guardrail -- nexus-cli mcp serve
```

- `mcp serve` finds the policy the same way as the other commands: `--policy`, then
  `$NEXUS_POLICY`, then `$NEXUS_HOME/policy.yaml`, then `./nexus.yaml`.
- Upstream MCP servers you want gated go under `mcp.upstreams` in the policy, not in `.mcp.json`
  (see [mcp.md](mcp.md)).
- Add `"--strict"` to `args` to approve every call.

### 2. HTTP(S) egress through the proxy

```bash
# nexus.yaml: let Claude Code reach its API
#   egress:
#     allow: ["api.anthropic.com", "*.github.com"]

nexus-cli ca init               # optional: per-request HTTPS policy (Node trusts it via NODE_EXTRA_CA_CERTS)
nexus-cli run -- claude
nexus-cli approve               # in another terminal
```

`run` sets the following for the child:

- `HTTP_PROXY`, `HTTPS_PROXY` (and lower-case), `NO_PROXY` and `NODE_USE_ENV_PROXY=1`;
- with a CA, `NODE_EXTRA_CA_CERTS` and the other CA variables.

To find hosts that are being denied, run `nexus-cli audit tail --decision deny`.

## GitHub Copilot CLI

Add the gateway to the Copilot CLI's MCP configuration (`~/.copilot/mcp-config.json`, or
interactively with `/mcp add`):

```json
{
  "mcpServers": {
    "nexus-security-guardrail": {
      "type": "local",
      "command": "nexus-cli",
      "args": ["mcp", "serve"],
      "tools": ["*"]
    }
  }
}
```

To gate its HTTP(S) egress as well, run it under the proxy. Add the hosts it uses to
`egress.allow` first, then run:

```bash
nexus-cli run -- copilot
```

## VS Code (GitHub Copilot)

`nexus-cli init` writes `.vscode/mcp.json`. VS Code uses a `servers` key with an explicit
`"type"`:

```json
{
  "servers": {
    "nexus-security-guardrail": {
      "type": "stdio",
      "command": "nexus-cli",
      "args": ["mcp", "serve"]
    }
  }
}
```

## Cursor

Put the same `mcpServers` block in **`.cursor/mcp.json`** in the project (or `~/.cursor/mcp.json`
for every project):

```json
{
  "mcpServers": {
    "nexus-security-guardrail": {
      "command": "nexus-cli",
      "args": ["mcp", "serve"]
    }
  }
}
```

If `nexus-cli` is not on the `PATH` the editor sees, use `"command": "npx"` with
`"args": ["-y", "@whoisnjoguu/nexus-cli", "mcp", "serve"]`.

## A Python agent with the `nexus` SDK

```bash
pip install "git+https://github.com/whoisnjoguu/nexus-cli#subdirectory=sdk/python"
# or from a checkout: pip install ./sdk/python   (add [requests] / [httpx] / [all] for the HTTP helpers)
```

```python
# agent.py
import nexus

nx = nexus.Client()  # under `nexus-cli run`: NEXUS_CONTROL_URL + NEXUS_CONTROL_TOKEN, token from NEXUS_PROXY_URL

print(nx.check(tool="read_file", args={"path": "README.md"}))

try:
    nx.require(tool="execute_shell", args={"cmd": "ls"})
except nexus.DeniedError as e:
    print("denied:", e)


@nexus.guard(tool="fs__write", args_from=["path"])
def write_file(path: str, content: str) -> None:
    ...
```

```bash
nexus-cli run --agent-id research-bot -- python agent.py
```

- Under `run`, plain `requests`/`httpx`/`urllib` calls already go through the proxy because
  `HTTP(S)_PROXY` is set.
- SDK checks and proxied requests share one policy engine, taint state and audit log, and are
  attributed to `research-bot` acting as you.
- Do not pass a different `agent_id` to `Client`. The run token is authoritative, and mismatches
  are denied.

See [sdk.md](sdk.md) and [`sdk/python/README.md`](../sdk/python/README.md).

## A Go program with `sdk/go`

```bash
go get github.com/whoisnjoguu/nexus-cli/sdk/go
```

```go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	sdk "github.com/whoisnjoguu/nexus-cli/sdk/go"
)

func main() {
	ctx := context.Background()
	c, err := sdk.Connect(sdk.ConnectOptions{}) // NEXUS_CONTROL_URL/TOKEN under `run`, else discovery files
	if err != nil {
		log.Fatal(err) // sdk.ErrNoDaemon when nothing is running
	}
	defer c.Close()

	resp, err := c.Check(ctx, sdk.CheckRequest{Tool: "read_file", Args: json.RawMessage(`{"path":"README.md"}`)})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("read_file:", resp.Decision, resp.Reason)

	err = c.Require(ctx, sdk.CheckRequest{Tool: "execute_shell", Args: json.RawMessage(`{"cmd":"ls"}`)})
	var denied *sdk.DeniedError
	if errors.As(err, &denied) {
		fmt.Println("execute_shell:", denied.Response.Decision, denied.Response.Reason)
	}

	// Ordinary HTTP already goes through the proxy: `run` sets HTTP(S)_PROXY.
	r, err := http.Get("http://example.com/")
	if err != nil {
		log.Fatal(err)
	}
	r.Body.Close()
	fmt.Println("GET example.com:", r.StatusCode)
}
```

```bash
go build -o agent . && nexus-cli run --agent-id go-agent -- ./agent
```

## `dev` as a background service plus `run --attach`

Run one long-lived gate per user, then attach agents to it:

```bash
nexus-cli policy protect                     # optional: move nexus.yaml to ~/.nexus/policy.yaml (0600)
nexus-cli policy pin                         # optional: refuse unreviewed policy edits
nexus-cli service install --dry-run          # preview the systemd unit / launchd agent / scheduled task
nexus-cli service install                    # listens on 127.0.0.1:8075 by default
nexus-cli service status

nexus-cli run --attach 127.0.0.1:8075 -- python agent.py
eval "$(nexus-cli run --attach 127.0.0.1:8075 --print-env)"   # or export the env into this shell
nexus-cli approve                            # answer prompts for the service
```

- Pass extra `dev` flags after `--`, for example `nexus-cli service install -- --strict`.
- Use `--env NEXUS_KEY_BACKEND=file` if the service cannot reach your keychain.
- `run --attach` mints the token with the same signing key as the service, so keep `NEXUS_HOME`
  (and `--key`, if you use it) identical in both. Otherwise the proxy rejects the token with
  "it uses a different signing key".
- `--print-env` emits:
  - `HTTP(S)_PROXY` (and lower-case), `NO_PROXY`, `NODE_USE_ENV_PROXY` and `NEXUS_PROXY_URL`;
  - `NEXUS_CONTROL_URL` and the check-only `NEXUS_CONTROL_TOKEN`;
  - the CA variables when interception is on.

See [service.md](service.md).

## CI: an agent in GitHub Actions

CI has no human to approve prompts. Use a policy without `hitl` outcomes (anything that would ask
waits `--approval-timeout`, default 2m, and is then denied). Sign the audit log so it can be
verified and archived.

```yaml
# .github/nexus-ci.yaml (example policy)
agent: ci-agent
default_action: deny
egress:
  allow: ["api.openai.com", "*.github.com"]
tools:
  - match: { method: GET }
    action: allow
audit:
  sign: true
```

```yaml
# .github/workflows/agent.yml
name: agent
on: [workflow_dispatch]

jobs:
  agent:
    runs-on: ubuntu-latest
    env:
      NEXUS_HOME: ${{ runner.temp }}/nexus
      NEXUS_KEY_BACKEND: file # no keychain on CI runners
      NEXUS_NOTIFY: "off"
      NEXUS_POLICY: .github/nexus-ci.yaml
    steps:
      - uses: actions/checkout@v4

      - name: Install nexus-cli
        run: |
          curl -fsSL https://raw.githubusercontent.com/whoisnjoguu/nexus-cli/master/install.sh \
            | INSTALL_DIR="$HOME/.local/bin" sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Lint policy
        run: nexus-cli policy lint --strict-warnings

      - name: Run the agent behind the gate
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          nexus-cli run --agent-id ci-agent --user-id "${{ github.actor }}@github" \
            --mitm off -- python agent.py

      - name: Verify audit log
        if: always()
        run: |
          nexus-cli audit verify --require-signed
          nexus-cli audit tail -n 50

      - name: Upload audit log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: nexus-audit
          path: |
            ${{ runner.temp }}/nexus/audit*.jsonl
            ${{ runner.temp }}/nexus/audit.pub
```

- `--mitm off` gates HTTPS per host only. To get per-request HTTPS policy, use `--mitm on` instead:
  `run` creates the CA under `NEXUS_HOME` and points `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `NODE_EXTRA_CA_CERTS` and the other CA variables at it.
- The audit signing key is created per job here. `audit verify` proves the log was not altered
  after it was written within the job. Archive `audit.pub` with the log, or keep a long-lived
  `audit.key_path` secret if you need signatures that persist across jobs.
- `run` exits with the agent's exit status, so a failing agent fails the step.
