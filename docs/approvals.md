# Approvals

When a call matches a `hitl` rule (or every call under `--strict`), nexus-cli holds it until a human
decides. Each running gateway (`nexus-cli dev`, `nexus-cli run`, `nexus-cli mcp serve`) queues the
request on an approval broker. You can answer it from several places, and the first answer wins:

- the `dev` terminal itself, when it is interactive;
- MCP elicitation, when the MCP client supports it;
- `nexus-cli approve` in another terminal;
- the local approvals web UI.

If nobody answers within `--approval-timeout`, the call is **denied** (fail closed).

Each answer is one of:

| Decision  | Effect                                                              |
| --------- | ------------------------------------------------------------------- |
| `once`    | Allow this call only                                                |
| `session` | Allow matching calls for the rest of this session                   |
| `always`  | Allow, and append an `allow` rule to the policy file (`nexus.yaml`) |
| `deny`    | Deny the call                                                       |

## `nexus-cli approve`

```bash
nexus-cli approve                         # interactive watcher
nexus-cli approve --quiet                 # … without the terminal bell
nexus-cli approve --list                  # print pending requests and exit
nexus-cli approve <id> --decision once    # decide one request: once|session|always|deny
nexus-cli approve --web                   # open the web UI in your browser
nexus-cli approve --web --no-open         # print the one-time UI link instead
nexus-cli approve --web --pid 12345       # pick the gateway when several are running
```

| Flag            | Meaning                                                                  |
| --------------- | ------------------------------------------------------------------------ |
| `--list`        | Print pending requests across all local gateways and exit                |
| `--decision`    | With a request id: `once`, `session`, `always` or `deny`                 |
| `--web`         | Mint a one-time login link for a gateway's web UI and open it            |
| `--no-open`     | With `--web`: print the link, do not start a browser                     |
| `--pid`         | With `--web`: the gateway's process ID (shown by `--list` as `kind/pid`) |
| `-q`, `--quiet` | Interactive watcher: do not ring the terminal bell on new requests       |

The interactive watcher discovers every running gateway, shows the oldest pending request, and takes
`y` (once), `s` (session), `a` (always) or `n` (deny). `q` quits. It rings the terminal bell when a
new request arrives.

Gateways advertise themselves with 0600 discovery files in `$NEXUS_HOME/control/` (default
`~/.nexus/control/`). Each file holds the loopback address and two random tokens for that
gateway's control API: the admin `token` used by `nexus-cli approve`, and a `check_token` that only
works for SDK decisions (see [Security model](#security-model)).

## Web UI

`nexus-cli approve --web` opens `http://127.0.0.1:<port>/ui#login=<code>` for one gateway. The page
shows:

- **Pending requests**, each with its agent, act-as user, tool or method, target, reason, params,
  age and a countdown to auto-deny. Buttons: **Allow once**, **Allow for session**, **Always**
  (asks for confirmation, then persists a rule) and **Deny**.
- **Recently decided**: the last 20 resolved requests, with the outcome and who resolved them.
  - `cli` means `nexus-cli approve`.
  - `web` means the web UI.
  - `timeout` means the request expired.
  - `elsewhere / caller gone` (a `cancelled` event) means the caller went away, or another approver
    (for example the `dev` terminal) answered first.

The page updates live over Server-Sent Events. If SSE is not available it falls back to
long-polling. Light and dark themes follow your OS setting. There are no external assets: the HTML,
JS and CSS are embedded in the binary.

The UI covers **one gateway**: the one chosen with `--pid`, or else the only one running. When
several are running and no `--pid` is given, it opens the gateway with the oldest pending request.
If none has anything pending, it opens the most recently started one. To watch every gateway at
once, use the terminal watcher (`nexus-cli approve`).

### Security model

The control API listens on `127.0.0.1` only. CLI clients authenticate with the bearer token from the
discovery file, and any request that carries `Authorization` must also:

- use the exact `Host` `127.0.0.1:<port>`;
- send no `Origin` header, which shuts out browsers.

The check-only token (`check_token`, which `nexus-cli run` hands to its child as
`NEXUS_CONTROL_TOKEN`) is accepted only on `GET /v1/status`, `POST /v1/check` and
`GET /v1/check/{id}`. Every approvals route answers it with `403`, so an agent under `run` cannot list
or decide its own requests through the API.

Browsers can't send that bearer token from a link, so the UI uses a separate cookie session:

1. `nexus-cli approve --web` calls `POST /v1/ui/login-code` with the bearer token. The gateway
   returns a random one-time code that expires after 60 seconds.
2. The page reads the code from the URL fragment. Fragments are never sent to servers or put in
   logs. The page then removes the code from the address bar and sends it to `POST /v1/ui/session`.
   That exchange requires a same-origin `Origin` header and a JSON body, and it consumes the code
   whether or not it succeeds.
3. The response sets an `HttpOnly; SameSite=Strict; Path=/` cookie named `nexus_ui_<port>`. The
   cookie has no `Secure` flag because the UI runs on plain-HTTP loopback. The port is part of the
   name because browsers don't separate cookies by port, so each gateway's session stays apart. The
   response also returns a per-session CSRF token, which the page keeps in `sessionStorage`.
   Sessions last 12 hours.

Every cookie-authenticated request must pass all of these checks:

- **Host** is `127.0.0.1:<port>` or `localhost:<port>`. Anything else gets `403`, which defeats DNS
  rebinding.
- **Origin**, if present, is `http://127.0.0.1:<port>` or `http://localhost:<port>`. Every
  state-changing request must send it; otherwise the response is `403`.
- **`X-Nexus-CSRF`** matches the session's CSRF token. Otherwise the response is `403`.
  - Reads need it too, so the cookie alone is never enough.
  - `EventSource` cannot set headers, so `GET /v1/events` alone accepts the token as `?csrf=`
    instead.

Other protections:

- A cookie session can't mint login codes.
- `POST /v1/ui/logout` ends the session.
- The gateway keeps codes and sessions in memory only, and drops them when it exits.

Every response carries these headers:

- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; …` with
  `frame-ancestors 'none'`, and no inline script or style

All request fields are agent-controlled, so the page renders them as text only, never as HTML.

### API

| Route                                  | Auth             | Purpose                                                            |
| -------------------------------------- | ---------------- | ------------------------------------------------------------------ |
| `GET /ui`, `/ui/app.js`, `/ui/app.css` | Host check       | The embedded page and its assets                                   |
| `POST /v1/ui/login-code`               | bearer           | Mint a one-time login code → `{code, url, expires}`                |
| `POST /v1/ui/session`                  | code + Origin    | Exchange a code → cookie + `{csrf, expires}`                       |
| `POST /v1/ui/logout`                   | cookie + CSRF    | End the session                                                    |
| `GET /v1/ui/state`                     | bearer or cookie | Pending, recent, timeout, endpoint info; `?wait=&since=` long-poll |
| `GET /v1/events`                       | bearer or cookie | SSE: `hello`, `added`, `decided`, `expired`, `cancelled`           |
| `GET /v1/approvals`                    | bearer or cookie | Pending requests (`?wait=&since=` long-poll)                       |
| `POST /v1/approvals/{id}`              | bearer or cookie | `{"decision":"once\|session\|always\|deny"}`                       |
| `GET /v1/status`                       | bearer or cookie | Endpoint info and pending count                                    |

"bearer" means the admin `token` from the discovery file. The check-only token gets `403` on every
route above except `GET /v1/status`. The SDK decision routes (`POST /v1/check`,
`GET /v1/check/{id}`) are documented in [sdk.md](sdk.md).

Each SSE event's `data` is a JSON object: `{type, request, decision, by, at}`.

## Desktop notifications

`dev`, `run` and `mcp serve` show a desktop notification when a new request starts waiting. The
notification reads "Approval needed: _agent_ → _tool target_", followed by how to answer:
`nexus-cli approve`, or the web UI URL while a UI session is signed in.

Notifications are rate-limited to one every 3 seconds. Requests that arrive faster are grouped into
one notification, for example "3 approvals pending".

| Platform | Mechanism                                                                                    |
| -------- | -------------------------------------------------------------------------------------------- |
| Linux    | `notify-send --app-name=nexus-cli -u critical`. Needs `notify-send` and a graphical session. |
| macOS    | `osascript -e 'display notification … with title …'`                                         |
| Windows  | PowerShell toast (`Windows.UI.Notifications`), falling back to a tray balloon (`NotifyIcon`) |

Request fields are untrusted, so notifications are hardened:

- Control and bidi-override characters are stripped from all text.
- Text is truncated to 200 characters.
- No shell is ever involved. On Linux the text is a separate argument, after `--`, with markup
  escaped. On macOS it is an escaped AppleScript string literal. On Windows it is passed in
  environment variables to a constant, base64-encoded script.

If no helper is available, notifications are silently disabled.

| Setting                   | Effect                                                          |
| ------------------------- | --------------------------------------------------------------- |
| `--notify auto` (default) | Notify when a helper is available                               |
| `--notify off`            | Never notify                                                    |
| `NEXUS_NOTIFY=off`        | Disable notifications for every command (`auto` is the default) |

## Environment variables

| Variable       | Meaning                                                               |
| -------------- | --------------------------------------------------------------------- |
| `NEXUS_HOME`   | Base directory; control discovery files live in `$NEXUS_HOME/control` |
| `NEXUS_NOTIFY` | `auto` (default) or `off`                                             |
