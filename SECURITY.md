# Security policy

nexus-cli is a security tool, and we take reports about it seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

1. Go to <https://github.com/whoisnjoguu/nexus-cli/security/advisories/new>. You can also open the
   repository's **Security** tab and choose **Report a vulnerability**.
2. Include:
   - the affected version (`nexus-cli version`) and OS;
   - the command, flags and policy involved;
   - steps to reproduce;
   - the impact you observed.

   A minimal proof of concept helps a lot.

We aim to acknowledge reports within a few days and will keep you updated in the advisory while
we work on a fix. Once a fix is released we publish the advisory and credit you, unless you would
prefer not to be named.

## Supported versions

Only the **latest release** gets security fixes. Upgrade before reporting if you can, and tell us
if the issue only affects an older release.

| Version                   | Supported   |
| ------------------------- | ----------- |
| Latest release            | Yes         |
| Older releases            | No          |
| Unreleased branches (dev) | Best effort |

## Scope

In scope: anything that lets an agent, a web page or another unprivileged party get around a
protection that nexus-cli claims to provide in [docs/threat-model.md](docs/threat-model.md). For
example:

- policy bypasses in the proxy, the HTTPS interception, the MCP gateway or `POST /v1/check`;
- forging or replaying identities in ways the token checks should prevent;
- an agent under `nexus-cli run` approving its own requests with the check-only token;
- DNS rebinding, CSRF or authentication bypasses on the control API, the approvals web UI or
  `mcp serve --http`;
- audit log tampering that `audit verify` does not detect;
- the protected-path guard or policy pin failing to stop policy edits made through gated calls;
- secrets (keys, tokens, injected credentials) leaking to the agent, logs or other users;
- vulnerabilities in the release artifacts, `install.sh` or the npm wrapper.

Out of scope, because the threat model explicitly does not cover them:

- attacks that need code execution as the same OS user as nexus-cli;
- traffic that never goes through the proxy;
- HTTPS details that are not visible when interception is off;
- malicious responses from upstream MCP servers or HTTP services;
- decisions made by a human approver;
- configurations that turn protections off, such as `dev --require-auth=false` or a non-loopback
  `--listen` / `--allow-remote`.

Reports about the upstream nexus-framework Gateway should go to that project.

## Hardening guidance

See [docs/threat-model.md](docs/threat-model.md#recommended-deployment-for-untrusted-agents) for
how to deploy nexus-cli in front of untrusted agents.
