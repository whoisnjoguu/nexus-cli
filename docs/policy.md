# Policy reference

The policy file (`nexus.yaml` by convention) decides what an agent may do. `nexus-cli dev`, `run`
and `mcp serve` all enforce the same policy, and so do the embeddable SDKs. Each request ends in
one of three decisions:

| Action  | Meaning                                                                        |
| ------- | ------------------------------------------------------------------------------ |
| `allow` | Runs without interruption.                                                     |
| `deny`  | Blocked outright.                                                              |
| `hitl`  | Waits for a human approval (terminal prompt, `nexus-cli approve`, or MCP elicitation). Fails closed on timeout. |

## Which file is used

Every command resolves the policy path the same way:

1. `--policy <path>`, when given explicitly
2. `$NEXUS_POLICY`
3. `$NEXUS_HOME/policy.yaml` (default `~/.nexus/policy.yaml`), if it exists — see
   [`policy protect`](#protection)
4. `./nexus.yaml`

When no file exists, the built-in **safe-tier default** applies (see [Default policy](#default-policy)).

## File layout

```yaml
agent: claims-processor-v1          # informational label shown at startup

default_action: deny                # allow | deny | hitl; empty = deny
escalate_when_tainted: true         # see Taints

egress:
  allow: ["*.github.com", "api.internal.company.com"]
  passthrough: ["*.pinned.example.com"]

providers:                          # broker access (request_access / get_credential)
  github:
    access: hitl
    credential: deny
    scopes: [repo, read:user]

tools:                              # ordered rules: the FIRST match wins
  - match: { method: GET, host: api.internal.company.com, path: "/v1/claims/**" }
    scope: claims:read
    action: allow
    taints: ["db:read"]
  - match: { tool: "fs__write_file", args: { path: "/workspace/**" } }
    action: allow
  - match: { tool: execute_shell }
    action: deny

mcp:                                # MCP gateway upstreams (see docs/mcp.md)
  upstreams: [...]

audit:                              # audit log settings (see docs/audit.md)
  path: ~/.nexus/audit.jsonl
```

### Top-level fields

| Field                   | Type             | Meaning |
| ----------------------- | ---------------- | ------- |
| `agent`                 | string           | Label only. |
| `default_action`        | action           | Decision when nothing else matches. Empty means `deny`. |
| `escalate_when_tainted` | bool             | Once a session is tainted, an *allowed* egress to a host outside `egress.allow` becomes `hitl`. |
| `egress.allow`          | host patterns    | Hosts reachable when no rule matched (see [Egress](#egress)). Also the taint allowlist. |
| `egress.passthrough`    | host patterns    | HTTPS hosts tunnelled without TLS interception. Only the host-level CONNECT decision applies. |
| `providers`             | map              | Broker-access rules per provider (see [Providers](#providers)). |
| `tools`                 | list of rules    | Ordered rules (see [Rules](#rules)). |
| `mcp`                   | object           | MCP gateway configuration; see [docs/mcp.md](mcp.md). |
| `audit`                 | object           | Audit log configuration; see [docs/audit.md](audit.md). |

Unknown keys anywhere in the file, including inside `mcp:` and `audit:`, are **errors**.

### Rules

| Field      | Type        | Meaning |
| ---------- | ----------- | ------- |
| `match`    | object      | What the rule applies to (below). |
| `action`   | action      | `allow`, `deny` or `hitl`. Empty means `default_action`. |
| `scope`    | string      | The token must carry this scope, otherwise the call is **denied** (`token missing required scope`). |
| `one_time` | bool        | Only with `allow`: the first matching call per session is allowed, later ones are denied. |
| `taints`   | [string]    | Labels stamped on the session when the rule matches (see [Taints](#taints)). |
| `inject`   | bool        | Requires `match.host`. With `dev --inject`, the outbound `Authorization` is replaced by a short-lived credential from the broker for the token's connection. |

### Match

A rule is either a **tool rule** (it has `tool` or `provider`) or an **HTTP rule** (`method`,
`host`, `path`). Empty fields are wildcards. A match with no criteria at all never matches, so
there is no accidental catch-all.

| Field      | Applies to | Syntax |
| ---------- | ---------- | ------ |
| `tool`     | MCP / SDK tool calls | Case-insensitive glob. `*` matches any run of characters except `/` (`fs__read_*`, `get_*`). Upstream MCP tools are named `<server>__<tool>`. |
| `provider` | tool calls | Same glob syntax, against the call's provider. |
| `args`     | tool rules only | Map of argument patterns (below). Ignored on HTTP rules. |
| `method`   | HTTP | An HTTP verb (`GET`, `POST`, …, case-insensitive) or `*` for any. |
| `host`     | HTTP | Exact host or a single leading `*.` label (`*.github.com` matches `api.github.com`, not `github.com`). Ports are ignored. No scheme, path or other wildcards. |
| `path`     | HTTP | Must start with `/`. `/**` suffix matches any sub-path; `*` matches one segment; otherwise exact. |

When a tool rule also sets `method`/`host`/`path`, those fields are ignored (lint warns).

#### Argument matching (`match.args`)

```yaml
- match:
    tool: "fs__write_file"
    args:
      path: "/workspace/**"         # path pattern
      mode: "!0777"                 # negated
      options.recursive: "false"    # dot path into nested objects
  action: allow
```

- Keys are dot paths into the arguments object. A literal key containing a dot is tried first.
  Traversing through an array visits every element.
- Values are globs. A leading `!` negates.
- Patterns starting with `/`, `~` or `./` are **path patterns**: `~` expands to the home
  directory, both sides are cleaned (`/workspace/../etc/passwd` is `/etc/passwd`), `*` matches
  within one segment and `**` any number of segments. Case-sensitive.
- Other patterns: `*` matches anything (including `/`), `?` one character; case-insensitive.
- For an array argument, a positive pattern matches if ANY element matches; a negated pattern if
  NO element matches.
- Numbers and booleans compare via their text form; objects via their JSON.
- A missing key never matches, negated or not.

## Evaluation order

For each request:

1. **Built-in guard** — a tool call whose arguments reference a protected nexus file is denied
   (`protected nexus file`, `Decision.Source = "guard"`). Nothing below can override it.
2. **Providers** — `get_credential` uses `providers.<name>.credential` (default **deny**:
   secretless). `request_access` uses `providers.<name>.access`; unknown providers fall through.
3. **Rules** — `tools` in order; the first matching rule decides:
   - missing `scope` → deny
   - `one_time` rule already consumed in this session → deny
   - tainted session + `escalate_when_tainted` + allowed egress to a host outside `egress.allow`
     → `hitl` (taint escalation)
   - otherwise the rule's action (stamping its taints, consuming `one_time`)
4. **Egress allowlist** — for HTTP requests when `egress.allow` is non-empty: listed hosts are
   allowed, all others denied.
5. **`default_action`**.

A `hitl` result is skipped (becomes `allow`, reason `session grant`) when the human already chose
"approve for this session" for the same shape of call: the same tool + provider, or the same
method + host. A grant never overrides `deny`, a scope failure or a consumed `one_time`, and it
covers taint escalation only if the approved prompt was one.

"Always allow" answers prepend an `allow` rule for the call to the policy file, inheriting the
original rule's scope, taints, `one_time` and `inject`.

## Sessions

Session state — taints, `one_time` consumption and grants — is kept per agent and human
(`agent_id|act_as` of the token). It expires after 12 hours idle.

### Taints

`taints: [label]` marks the session as having touched sensitive data. With
`escalate_when_tainted: true`, any later egress that would be allowed to a host **not** in
`egress.allow` needs a human approval — this catches read-then-exfiltrate chains.

### `one_time`

A `one_time: true` allow rule permits one call per session. Consumption is keyed by the rule's
fingerprint (method, host, path, tool, scope and args), so editing those fields makes a fresh
rule; changing only the action or taints doesn't.

### Persistence

`dev`, `run` and `mcp serve` keep taints, `one_time` consumption and the ids of spent
`--single-use` tokens under `$NEXUS_HOME/state/`:

| File             | Contents                                   | Expires                      |
| ---------------- | ------------------------------------------ | ---------------------------- |
| `jti.json`       | spent single-use token ids                  | at token expiry (≥ 1 minute) |
| `sessions.json`  | taints + consumed `one_time` per session   | 12 h after the last change   |

The directory is 0700, files are 0600 and written atomically (temp file + rename) under a
cross-process lock, so concurrent nexus-cli processes share one view: two processes racing on
the same token id see exactly one success. Session sets only grow (writers merge by union).
Grants are not persisted: a restart asks again.

`--ephemeral-state` keeps everything in memory, as earlier versions did.

Trade-offs:

- A **corrupt** state file is logged, moved aside to `<file>.corrupt` and treated as empty.
  This fails open (spent tokens and `one_time` rules could be reused once) so a damaged file
  can't take the gate down; the `.corrupt` copy is kept for investigation.
- The replay guard fails **closed**: if the state file can't be written, the token is rejected.
- A session store write failure is logged and the engine continues from memory.
- Two processes evaluating the same session concurrently each hydrate it when they first see
  it; a `one_time` rule used in one process after the other loaded the session can be used once
  more there.

## Providers

```yaml
providers:
  github:
    access: hitl        # request_access: allow | hitl | deny (empty → tools/default)
    credential: deny    # get_credential: default deny (agents never see raw tokens)
    scopes: [repo]      # OAuth scopes requested for this provider
```

Provider names are case-sensitive keys; two names differing only in case are an error. Allowing
`credential` is a lint warning, because it hands raw tokens to the agent.

## Egress

`egress.allow` is consulted only when **no rule matched** an HTTP request: listed hosts are
allowed, others denied. It is also the "safe" list for taint escalation. `egress.passthrough`
hosts are tunnelled without TLS interception, so path and method rules can't apply to them.
Patterns follow the `host` syntax above. TLD-wide patterns such as `*.com` are lint warnings.

## Default policy

Used when no policy file exists: `default_action: hitl`, `escalate_when_tainted: true`, and:

| Tool / request                                      | Action |
| --------------------------------------------------- | ------ |
| `sampling/createMessage`                            | hitl   |
| `resources/read`, `prompts/get`                     | allow  |
| `execute_shell`                                     | deny   |
| `*delete*`                                          | hitl   |
| `read_*`, `list_*`, `search_*`, `get_*`             | allow  |
| `*__read_*`, `*__list_*`, `*__search_*`, `*__get_*` | allow  |
| `GET`, `HEAD` requests                              | allow  |

The read-only globs are anchored at a word start: `read_file`, `fs__read_file`,
`github__get_issue` and `list_repos` are allowed, while `forget_password`, `budget_delete`,
`target_delete` or `thread_reply` fall through to `hitl`. camelCase tools (`getIssue`) also ask.

## Validation and `policy lint`

Files are parsed strictly. **Errors** make `dev`, `run`, `mcp serve`, `policy test` and hot
reload refuse the file:

- unknown keys (reported with line numbers), malformed YAML
- unknown `action` / `default_action` / provider `access` / `credential`
- unknown HTTP `method`
- invalid globs in `tool`, `provider`, `path`, `args` values; invalid `host` / egress patterns
- `one_time` on a rule whose effective action isn't `allow`
- `inject: true` without `match.host`
- empty strings in `taints` or provider `scopes`, empty provider names
- providers that differ only in case

**Warnings** load fine but are flagged:

- empty match, or `args` without `tool`/`provider` → "rule never matches"
- tool rules with `method`/`host`/`path` (ignored), paths not starting with `/`
- `tool: "*"` or `host: "*"` with `allow`; substring globs like `*get*` with `allow`
- TLD-wide hosts (`*.com`); provider `credential: allow`
- rules shadowed by an earlier, broader rule → "unreachable"

```bash
nexus-cli policy lint                    # exit 1 on errors
nexus-cli policy lint --strict-warnings  # exit 1 on warnings too
nexus-cli policy lint --json             # {"path","errors","warnings","issues":[{severity,path,message}]}
```

```text
error tools[2].action: unknown action "alow" (want allow|deny|hitl)
warning tools[4]: unreachable: shadowed by tools[1] (the first matching rule wins)
```

`nexus-cli doctor` reports the counts, the pin status and whether the policy sits in the
current directory.

## Hot reload

`dev`, `run` and `mcp serve` poll the policy file every second (mtime, size, then SHA-256 — no
fsnotify). On `dev` and `mcp serve`, `SIGHUP` forces a reload (`run` forwards `SIGHUP` to its
child instead). A changed file is loaded strictly (pin check, parse, validation):

- success → the engine switches atomically: `[nexus] policy reloaded from <path> (sha256:<12 hex>)`
- failure → the current policy stays: `[nexus] policy reload failed: <error> (keeping the current policy)`.
  A deleted file also keeps the current policy.

Each attempt is audited: tool `policy/reload`, decision `allow`/`deny`, the error as reason,
target `<path>#sha256:<12 hex>`. A failure is reported once per distinct content.

On reload, taints and `one_time` consumption are kept; session grants are cleared because the
human approved them under the old rules. Changes to `egress.passthrough`, `mcp:` and `audit:`
take effect on restart. Disable with `--no-reload`.

nexus-cli's own writes (`policy edit`, "always allow") replace the file atomically and keep its
mode (new files are 0600), so a reload never reads a partial file.

## Protection

The gated agent usually works in the directory that holds `./nexus.yaml`, and may run tools that
can write files. Three layers keep it from rewriting its own rules:

### Built-in guard

Always on in `dev`, `run` and `mcp serve`. Before any rule, a **tool call** is denied when any
string in its arguments — recursively through objects and arrays — resolves inside:

- the active policy file
- the nexus home (`$NEXUS_HOME`, default `~/.nexus`: signing keys, CA, pin, state, default audit log)
- the configured audit log's directory
- the pin file

Strings are resolved like a filesystem would: `file://` is stripped, `~` expands, relative paths
are joined to the working directory, `..` is cleaned, and symlinks are evaluated — including
the parent directories of files that don't exist yet and dangling links. Single-line command
strings (≤ 4 KiB) are also split into words, so `sed -i s/deny/allow/ nexus.yaml` or
`echo x >> ~/.nexus/policy.pin` are caught. The decision is `deny` with reason
`protected nexus file` and is not affected by rules, grants, reloads or `--strict`.

HTTP proxy requests aren't affected.

Limitations: only the protected paths and their contents are guarded, not their parent
directories (an agent could rename the whole workspace); words in multi-line content (e.g. a
script being written) aren't inspected; and the guard sees only arguments, so a tool that
derives paths internally (or a shell command built indirectly) can still reach them. Combine it
with `policy protect` and `policy pin`.

### `policy protect`

```bash
nexus-cli policy protect          # moves the policy to $NEXUS_HOME/policy.yaml (0600), prints the path
nexus-cli policy protect --keep   # copy, leaving the original
```

The new location wins over `./nexus.yaml` in the path precedence, so no flags are needed
afterwards. An existing pin moves with the file. `dev` and `run` print a warning while the policy
is inside the current directory:

```text
[nexus] warning: policy ./nexus.yaml is inside the agent's workspace — the agent could edit it; move it with 'nexus-cli policy protect' or rely on the built-in guard
```

### `policy pin`

```bash
nexus-cli policy pin              # record sha256 in $NEXUS_HOME/policy.pin
nexus-cli policy pin --remove
```

The pin file holds `<sha256>  <absolute path>` lines (one per pinned policy). While a policy is
pinned, `dev`, `run` and `mcp serve` refuse to start with content that has a different hash, and
hot reload refuses to load it. Each refusal is audited as tool `policy/pin`, decision `deny` (at
startup it goes to the default audit log, since the unapproved file's `audit:` section isn't
trusted). To approve a change, review it and run `policy pin` again — a running proxy picks it up
on the next poll — or restart with `--accept-policy-change`, which re-pins and audits an `allow`.
Writes made through nexus-cli (`policy edit`, "always allow" approvals) re-pin automatically.

## Commands

| Command | Description |
| ------- | ----------- |
| `nexus-cli policy lint [--json] [--strict-warnings]` | Validate the policy. |
| `nexus-cli policy test --method/--url/--tool/--provider/--scopes` | Dry-run a request. |
| `nexus-cli policy edit` | TUI editor (refuses to save a policy with errors). |
| `nexus-cli policy protect [--keep]` | Move the policy to `$NEXUS_HOME/policy.yaml`. |
| `nexus-cli policy pin [--remove]` | Pin the policy's SHA-256. |

All accept `--policy`. `dev` and `run` also take `--no-reload`, `--ephemeral-state` and
`--accept-policy-change`.
