# Audit log

Every authorization decision made by `nexus-cli dev`, `nexus-cli run`, `nexus-cli mcp serve`
(including SDK checks sent to their control API, see [sdk.md](sdk.md)) and the in-process Go
`LocalGate` is appended to a hash-chained JSONL log. This document covers the format, what it protects
against, and how to operate it.

## Threat model

| Attacker                                                                  | Can they rewrite history undetected?                                                                      | What catches them                                          |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Someone who edits / deletes / reorders lines by hand                      | No                                                                                                        | `audit verify` (hash chain)                                |
| Someone who strips signatures from recent entries                         | No                                                                                                        | `audit verify` (signed → unsigned downgrade is an error)   |
| Someone with a different signing key                                      | No                                                                                                        | `audit verify` (unknown key id / signature mismatch)       |
| **A process running as your OS user** (including the agent being audited) | **Yes, locally** – it can read `audit.key`, rewrite the files, recompute the chain and re-sign everything | An **anchor** stored off the machine, or a **remote sink** |

The hash chain and signatures make tampering _evident_ only relative to something the
attacker cannot also rewrite. Locally, anybody with your UID can recompute everything. The two
mechanisms that move trust off the box are:

1. **Anchors** – periodically record `nexus-cli audit head` somewhere else (a git commit, a
   ticket, a chat message, a remote log). Later, `nexus-cli audit verify --anchor <hash>` fails
   unless the current chain still contains that exact entry, which proves nothing up to the
   anchor was rewritten, reordered, deleted or truncated.
2. **Sinks** – stream every entry to a webhook or syslog collector as it is written. The remote
   copy is the evidence; the local file is a convenience.

Signatures (with a key separate from the token-signing key) add attribution and stop
casual/partial edits; they matter most once the private key is kept away from the agent (e.g.
on a different account or a dedicated host running the proxy).

## Format

One JSON object per line. Fields:

| Field                                                                      | Notes                                                                                                                                                |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seq`                                                                      | Monotonic sequence number, continuous across rotation (absent on entries written before v2; those are numbered by position)                          |
| `ts`                                                                       | UTC time                                                                                                                                             |
| `jti`, `agent`, `act_as`, `tool`, `target`, `scopes`, `decision`, `reason` | Decision context                                                                                                                                     |
| `session`, `rule`, `args_hash`, `source`                                   | Optional: session id, matched rule summary, sha256 of request params/args (`audit.HashArgs`), decision source (`policy`, `hitl`, `session-grant`, …) |
| `key_id`                                                                   | First 16 hex chars of sha256(public key) of the signer                                                                                               |
| `prev_hash`                                                                | `hash` of the previous entry (`""` for the very first)                                                                                               |
| `hash`                                                                     | hex sha256 of the entry's JSON with `hash` and `sig` set empty                                                                                       |
| `sig`                                                                      | base64 Ed25519 signature over the `hash` string                                                                                                      |

All new fields are `omitempty`, so logs written by older versions hash and verify unchanged.

## Files and rotation

```
$NEXUS_HOME (default ~/.nexus)/
  audit.jsonl                               active file
  audit-20261024T101500Z-48211.jsonl        rotated: <UTC time>-<last seq in file>
  audit.jsonl.lock                          advisory lock shared by all writers
  audit.key                                 Ed25519 seed (0600), separate from ed25519.key
  audit.pub                                 public key(s), one base64 key per line
```

When the active file reaches `max_bytes` (default 10 MiB; negative disables rotation) it is
renamed and a new file is started whose first `prev_hash` is the last hash of the rotated file.
`verify`, `tail`, `export` and `head` read the rotated set (ordered by seq) followed by the
active file. Deleting a rotated file breaks the chain; archive old files rather than deleting
them, or anchor before pruning.

Writes are `fsync`ed by default. Multiple processes (e.g. `dev` and `mcp serve`) can write the
same log: an advisory lock (`flock` on Unix, `LockFileEx` on Windows) serializes appends and
each writer re-reads the chain head if another process wrote or rotated in between. A torn final
line left by a crash is truncated by the next writer.

## Commands

```bash
nexus-cli audit tail -n 50 --decision deny        # recent decisions (filters: --agent --decision --since)
nexus-cli audit tail -f --json                    # follow new entries (survives rotation)
nexus-cli audit verify                            # chain + signatures (uses audit.pub if present)
nexus-cli audit verify --require-signed --pubkey ./audit.pub
nexus-cli audit head                              # seq / hash / time to store off-machine
nexus-cli audit verify --anchor <hash>            # prove history up to <hash> is intact
nexus-cli audit export --format csv --since 24h > decisions.csv
nexus-cli audit keygen                            # create/print the audit signing public key
```

The `audit` commands read the log named by `--file`, else `audit.path` of the active policy file
(same lookup as `--policy` elsewhere: `$NEXUS_POLICY`, `$NEXUS_HOME/policy.yaml`, `./nexus.yaml`),
else `$NEXUS_HOME/audit.jsonl`. CSV exports prefix cells starting with
`= + - @` with `'` to prevent spreadsheet formula injection.

### Anchoring workflow

```bash
# e.g. daily, from cron or CI, somewhere the agent can't write:
nexus-cli audit head --json >> anchors.jsonl && git commit -am "audit anchor" && git push

# during review / incident response:
nexus-cli audit verify --anchor "$(tail -1 anchors.jsonl | jq -r .hash)" --require-signed
```

## Configuration (`audit:` in nexus.yaml)

`dev`, `run` and `mcp serve` open the log described by the policy's `audit:` block (`--no-audit`
disables it). Changes to this block need a restart; hot reload does not apply them.

```yaml
audit:
  path: /var/log/nexus/audit.jsonl # default $NEXUS_HOME/audit.jsonl; absolute — "~" is not expanded
  key_path: /secure/nexus/audit.key # default $NEXUS_HOME/audit.key (only used with sign: true)
  max_bytes: 10485760 # 0 = default 10 MiB, negative = never rotate
  fsync: true # default true
  sign: true # load/create $NEXUS_HOME/audit.key (key_path overrides)
  sinks:
    - type: webhook
      url: https://siem.example.com/ingest
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}" # ${ENV} is expanded
    - type: syslog
      network: udp # "" + "" addr = local syslog daemon (Unix only)
      addr: logs.example.com:514
      tag: nexus-audit
```

Embedding the logger in Go:

```go
var cfg audit.Config            // unmarshalled from nexus.yaml
logger, err := cfg.Open()       // or: opts, err := cfg.Options(); audit.OpenWithOptions(path, opts)
defer logger.Close()
```

Sinks only see entries after they are durably written, and a sink failure never fails `Log`.
The webhook sink POSTs JSON arrays (≤100 entries) from a background goroutine with a bounded
queue of 1000 entries: when the collector is slow or down it retries with exponential backoff
(on network errors, 429 and 5xx) and drops the _oldest_ queued entries, counted by
`WebhookSink.Dropped()`. `Close` flushes for up to 5 s. The syslog sink sends each entry as JSON
(facility AUTH; `deny` at WARNING, others at INFO) and is not available on Windows.
