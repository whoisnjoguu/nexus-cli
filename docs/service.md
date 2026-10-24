# Running nexus-cli as a service

`nexus-cli service` installs `nexus-cli dev` as a **per-user** background service, so the
zero-trust proxy is always available for `nexus-cli run --attach`, `nexus-cli approve` and your
agents. It needs no root or administrator rights (see the Windows notes below).

| Platform | Mechanism                       | Definition                                                    |
| -------- | ------------------------------- | ------------------------------------------------------------- |
| Linux    | systemd **user** unit           | `~/.config/systemd/user/nexus-cli.service`                    |
| macOS    | launchd agent                   | `~/Library/LaunchAgents/dev.nexus-cli.plist`                  |
| Windows  | Task Scheduler task (at log on) | task `nexus-cli` running `%NEXUS_HOME%\nexus-cli-service.cmd` |

## Quick start

```bash
cd ~/my-project
nexus-cli service install --dry-run           # preview the unit/plist/command; changes nothing
nexus-cli service install --policy nexus.yaml # install, enable and start
nexus-cli service status                      # exits non-zero unless running and healthy
nexus-cli run --attach 127.0.0.1:8075 -- claude
nexus-cli approve                             # answer approval prompts
```

## Commands

| Command                                    | What it does                                                      |
| ------------------------------------------ | ----------------------------------------------------------------- |
| `service install [flags] [-- <dev flags>]` | Write the definition, enable and start it, wait for health        |
| `service uninstall`                        | Stop, disable and remove the definition and `service.json`        |
| `service start` / `stop` / `restart`       | Control the installed service (`start`/`restart` wait for health) |
| `service status [--json]`                  | Platform state + health endpoint + control discovery entry        |
| `service logs [-f] [-n 100]`               | Recent log lines; `-f` follows, `-n 0` shows everything           |

### `service install` flags

| Flag                 | Default          | Notes                                                                                                                                                         |
| -------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--listen`           | `127.0.0.1:8075` | Must be a loopback address with a fixed port, unless `--allow-remote`.                                                                                        |
| `--policy`           | lookup order     | `$NEXUS_POLICY`, else `$NEXUS_HOME/policy.yaml` if it exists, else `./nexus.yaml`. Resolved to an **absolute** path; refused if it lives in a temp directory. |
| `--mitm`             | `auto`           | `auto`, `on` or `off`, passed to `dev`.                                                                                                                       |
| `--approval-timeout` | `60s`            | Passed to `dev`.                                                                                                                                              |
| `--env KEY=VAL`      |                  | Repeatable. `--env KEY` copies the value from the current environment.                                                                                        |
| `--force`            |                  | Replace an existing installation (and skip the "port in use" check, since it may be ours).                                                                    |
| `--dry-run`          |                  | Print the definition and the commands that would run; touch nothing.                                                                                          |
| `--allow-remote`     |                  | Allow a non-loopback `--listen`. The proxy then accepts connections from the network.                                                                         |
| `--no-hardening`     |                  | Linux: omit the systemd sandboxing directives.                                                                                                                |
| `-- <dev flags>`     |                  | Anything after `--` is appended to `dev`, for example `-- --strict --single-use`.                                                                             |

Install refuses to proceed when:

- the policy file resolves inside a temp directory (`$TMPDIR`, `/tmp`, `/var/tmp`, …), because it
  would vanish on reboot. The same applies to the `nexus-cli` executable itself (e.g. `go run`);
- `--listen` is not loopback and `--allow-remote` is not set;
- something already listens on `--listen` (without `--force`). If it is another nexus proxy, the
  error says so. A dry run only warns.

It warns (but continues) when the policy file does not exist yet or `NEXUS_HOME` is in a temp dir.

## NEXUS_HOME must match

The service gets an explicit `NEXUS_HOME` (your current `$NEXUS_HOME`, or `~/.nexus`), written into
the unit/plist/script. It shares everything with your shell through that directory:

- `$NEXUS_HOME/control/` — the discovery entry that `run --attach`, `approve`, `mcp status` and
  `doctor` use to find the running `dev`;
- the CA (`ca/`), signing keys, the audit log, and `service.json`.

If you later use a different `NEXUS_HOME` in a shell, that shell won't see the service's approvals.
`service install` also passes through `NEXUS_KEY_BACKEND` and `NEXUS_GATEWAY_URL` when they are set.
Add other variables with `--env`. A service doesn't inherit your shell's environment.

## Approvals under a service

A service has no terminal: stdin is `/dev/null` (systemd, launchd) or `NUL` (Windows). `dev` notices
this and uses **broker-only** approvals, printing
`approvals: run 'nexus-cli approve' in another terminal`. Answer prompts with `nexus-cli approve`
(same `NEXUS_HOME`). Calls nobody answers are denied after `--approval-timeout`, so they fail
closed.

## `service status`

`status` combines three signals and exits non-zero unless the service is running **and** healthy:

1. **platform state:** `systemctl --user show` (ActiveState `active` / `inactive` / `failed`, main
   PID), `launchctl print gui/<uid>/dev.nexus-cli` (state, pid, last exit code) or
   `schtasks /Query /TN nexus-cli /FO LIST` (Status `Running` / `Ready`);
2. **liveness:** `GET http://<listen>/_nexus/health`, with the listen address read from
   `$NEXUS_HOME/service.json` (written at install) or the installed definition;
3. **discovery:** the `dev` entry in `$NEXUS_HOME/control` (matched by PID, then by listen
   address). If this is missing, `run --attach`/`approve` won't find the service, which usually
   means `NEXUS_HOME` differs.

`--json` prints the same report as an object. The control token is never printed.

## Platform details

### Linux (systemd user unit)

The unit contains:

- `ExecStart=` with the absolute executable and `dev` flags;
- `WorkingDirectory=` set to the policy's directory, and `Environment="NEXUS_HOME=…"`;
- `Restart=on-failure`, `RestartSec=2` and `UMask=0077`.

Values use systemd quoting (`%`→`%%`, `$`→`$$`, and double quotes with C escapes for spaces and
quotes). Hardening on by default:

```ini
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths="-/home/me/.nexus" "-/home/me/my-project"
```

`ProtectSystem=strict` makes the filesystem read-only except `NEXUS_HOME` and the policy directory
(created before start). If your policy writes somewhere else (an absolute `audit.path` for example),
add `--no-hardening`.

Install runs `systemctl --user daemon-reload` then `systemctl --user enable --now nexus-cli`. Logs go
to the journal: `service logs` runs `journalctl --user -u nexus-cli`.

User services stop when you log out. To keep the proxy running without a session, enable lingering:
`loginctl enable-linger $USER`. `install` prints this hint when linger is off.

### macOS (launchd agent)

The plist (XML-escaped) has:

- `ProgramArguments`, `EnvironmentVariables` and `WorkingDirectory`;
- `RunAtLoad`, `KeepAlive` → `SuccessfulExit=false` (restart on crash, not on a clean exit) and
  `ThrottleInterval` 10;
- `Umask` 077, and stdout/stderr to `$NEXUS_HOME/logs/service.log`.

It loads with `launchctl bootstrap gui/<uid> <plist>`, falling back to `launchctl load -w`. Other
commands:

- `stop`: `launchctl kill SIGTERM`. Since that exit is clean, launchd won't restart it.
- `start`: `launchctl kickstart`.
- `uninstall`: `launchctl bootout` (fallback `unload -w`).
- `service logs`: tails the log file.

### Windows (Scheduled Task)

`install` writes `%NEXUS_HOME%\nexus-cli-service.cmd`, which:

- sets the environment, `cd`s to the policy directory and runs `dev`;
- redirects stdin from `NUL` and appends output to `%NEXUS_HOME%\logs\service.log`.

The script uses cmd escaping and MSVC argument quoting, so paths with spaces, `&`, `<`, `>` and
`%` work. Install then registers and starts it:

```text
schtasks /Create /SC ONLOGON /TN nexus-cli /TR "\"C:\...\nexus-cli-service.cmd\"" /RL LIMITED /F
schtasks /Run /TN nexus-cli
```

Limitations:

- The task runs at **logon** for the current user. It isn't a Windows service: it doesn't run
  before logon and it isn't restarted on crash. Use `service restart`.
- Creating an `ONLOGON` task can need an elevated prompt, depending on local policy.
- A console window may be visible while it runs.
- `/TR` is limited to 261 characters. A very long `NEXUS_HOME` path is rejected.
- `stop` uses `schtasks /End`. If a `dev` process survives it, check `service status` and end it by
  PID.
- `status` parses English `schtasks /Query` output. On other locales the state may show as unknown.
  The health and control checks still work.
- `NEXUS_HOME` and other paths can't contain `"`.
- `--env KEY=` (empty value) unsets the variable in the script.

## Files

| Path                                | Purpose                                              |
| ----------------------------------- | ---------------------------------------------------- |
| `$NEXUS_HOME/service.json`          | Name, platform, listen, policy, args (0600)          |
| `$NEXUS_HOME/logs/service.log`      | macOS/Windows service output                         |
| `$NEXUS_HOME/nexus-cli-service.cmd` | Windows launcher script                              |
| `$NEXUS_HOME/control/*.json`        | Discovery entry of the running `dev` (all platforms) |

## Troubleshooting

- **`status` says running but not healthy:** check `service logs`. Common causes are a policy parse
  error or the port being in use.
- **`health` ✔ but `control` ✖:** a different `NEXUS_HOME` in your shell, or another process
  answering on that port.
- **Moved the binary or the policy:** re-run `service install --force`. The definition stores
  absolute paths.
- **`doctor`** reports whether the service is installed, running and healthy (once wired in).
