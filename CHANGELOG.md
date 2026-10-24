# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `nexus-cli run -- <command>` runs a command behind an in-process gated proxy.
  - It mints a dual-actor token and wires `HTTP(S)_PROXY`, `NEXUS_PROXY_URL`, the CA bundle
    variables and the control endpoint into the child's environment.
  - `--attach` reuses a running `dev`, and `--print-env` prints the environment for `eval`.
- HTTPS interception: `nexus-cli ca init|install|uninstall|path|fingerprint`, plus `--mitm auto|on|off`
  on `dev` and `run`.
  - Path, method, `one_time`, taint and `inject` rules now apply to HTTPS.
  - Hosts listed under `egress.passthrough` are tunnelled without interception.
- Out-of-band approvals:
  - `nexus-cli approve`: an interactive watcher, plus `--list`, `--decision` and `--web`.
  - Approval timeouts.
  - A local approvals web UI with one-time login links and live updates.
  - Desktop notifications (`--notify`, `NEXUS_NOTIFY=off`) and a terminal bell.
- Key management:
  - OS keychain backend (`NEXUS_KEY_BACKEND=auto|keychain|file`) and key ids (`kid`).
  - `nexus-cli keys show|rotate|migrate|prune|jwks`.
- Audit log:
  - Optional Ed25519 signatures (`audit.sign`), size-based rotation and cross-process locking.
  - Anchors (`audit head`, `audit verify --anchor`).
  - Webhook and syslog sinks, and `audit export --format jsonl|csv`.
  - `audit keygen`, and `tail` filters (`--agent`, `--decision`, `--since`, `-f`, `--json`).
  - The `audit:` policy block is used by `dev`, `run`, `mcp serve` and the `audit` commands.
- MCP gateway:
  - Concurrent request handling with full passthrough of upstream tools, resources and prompts.
  - Streamable HTTP transport (`mcp serve --http`, `--http-token`, `--http-allowed-host`,
    `--stdio`).
  - Upstream supervision and restart (`--no-restart`), and `--call-timeout`.
  - Approvals via MCP elicitation and `nexus-cli approve`.
  - `nexus-cli mcp status`.
- Policy:
  - Argument-aware tool rules (`args:` matchers).
  - Strict parsing and `nexus-cli policy lint` (`--json`, `--strict-warnings`).
  - Hot reload on file change or `SIGHUP` (`--no-reload`).
  - `nexus-cli policy protect` and `nexus-cli policy pin` (`--accept-policy-change`).
  - A built-in guard that denies tool calls touching nexus-cli's own files.
- Session state persists across restarts (replay guard, `one_time` and taints) under
  `$NEXUS_HOME/state` (`--ephemeral-state` to opt out).
- `nexus-cli service install|uninstall|start|stop|restart|status|logs` runs `dev` as a per-user
  systemd unit, launchd agent or Windows scheduled task.
- SDK decision API:
  - Control endpoint `POST /v1/check` and `GET /v1/check/{id}` on `dev`, `run` and `mcp serve`,
    sharing their policy engine, taints, approvals and audit log.
  - A daemon `Client` in `sdk/go`.
  - Python SDK 0.2.0 (`nexus-agent-sdk`): discovery-based `Client`/`AsyncClient`, `guard`
    decorator, and `requests`/`httpx` helpers.
- `nexus-cli doctor` reports keychain, audit chain, MCP upstream and service health.
- `nexus-cli identity mint -q` prints only the token.
- CI runs on Linux, macOS and Windows, and tests the Python SDK.
- Documentation: `docs/threat-model.md`, `docs/recipes.md`, `SECURITY.md`, and guides for
  approvals, audit, keys, MCP, policy, SDK and service.

### Changed

- `dev` binds to `127.0.0.1` by default. Use `--listen` to choose another address.
- Proxy tokens are reusable until they expire. `identity mint --single-use` or `dev --single-use`
  makes them one-shot. The proxy also accepts `Proxy-Authorization: Basic` credentials.
- Policy path precedence is `--policy`, `$NEXUS_POLICY`, `$NEXUS_HOME/policy.yaml`, then
  `./nexus.yaml`.
- Default and scaffolded tool globs are anchored at word starts (for example, `*get*` no longer
  matches `forget_password`). `method: "*"` matches any method.
- The proxy no longer draws approval prompts itself when it has no terminal. Without an approver,
  calls that need approval fail closed.
- `--policy` help no longer shows a misleading `nexus.yaml` default.

### Fixed

- The proxy speaks HTTP/1.1 upstream, which fixes 502s caused by HTTP/2 ALPN negotiation. It also
  reports clients that reject the interception CA.
- `--strict` now escalates policy allows to approval. Previously it was a no-op when a policy
  engine was loaded.
- The scaffolded `inject` rule for `api.github.com` was shadowed by the generic `GET` rule.
- Windows: audit rotation and repair work while handles are open, and Winsock connection resets
  are detected.

### Security

- The proxy strips inbound `X-Nexus-*` headers and sets the verified identity headers itself.
- `CONNECT` without credentials gets `407` before any TLS handshake. Intercepted requests whose
  `Host` differs from the `CONNECT` target (domain fronting) are rejected.
- The control API has a separate check-only token. `run` gives the child only that token, so a
  gated agent cannot approve its own requests.
- The control API, approvals UI and MCP HTTP enforce `Host`/`Origin` checks (DNS rebinding), and
  the web UI also requires a session cookie and a CSRF token.
- Group- or world-readable signing and CA key files are refused. The retired-key list is signed.
- Policy protection: the protected-path guard, pinning, and a warning when the policy is inside the
  workspace.
- `audit export --format csv` escapes spreadsheet formulas.

[Unreleased]: https://github.com/whoisnjoguu/nexus-cli/compare/dev-build...HEAD
