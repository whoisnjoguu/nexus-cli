# @whoisnjoguu/nexus-cli (npm launcher)

Run [nexus-cli](https://github.com/whoisnjoguu/nexus-cli) with zero install — this package downloads
the right release binary for your platform on first use and execs it.

```bash
# start the MCP gateway (no prior install)
npx -y @whoisnjoguu/nexus-cli mcp serve --strict

# any nexus-cli command works
npx -y @whoisnjoguu/nexus-cli version
npx -y @whoisnjoguu/nexus-cli login --provider google-drive --gateway "$NEXUS_GATEWAY_URL"
```

## Register with an MCP host (no mcp.json by hand)

**Claude Code:**

```bash
claude mcp add nexus -- npx -y @whoisnjoguu/nexus-cli mcp serve --strict
```

**VS Code / Copilot:**

```bash
code --add-mcp '{"name":"nexus","command":"npx","args":["-y","@whoisnjoguu/nexus-cli","mcp","serve","--strict"]}'
```

The binary is cached in this package's `vendor/` directory and matched to the package version.
Prefer a real install? Use `brew install whoisnjoguu/tap/nexus-cli`, `go install`, or the
[install script](https://github.com/whoisnjoguu/nexus-cli#install).
