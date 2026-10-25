# Token-signing keys

`nexus-cli` signs dual-actor tokens with an Ed25519 key. Anyone who holds the 32-byte seed can
mint tokens with any `sub`, `act_as` and `scopes`, so where the seed lives matters.

## Backends

Selected with `NEXUS_KEY_BACKEND` (default `auto`):

| Value      | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file`     | Base64 seed in `$NEXUS_HOME/ed25519.key` (default `~/.nexus/ed25519.key`), created `0600` in a `0700` directory. On Unix a key file accessible by group/other is refused (`chmod 600 <path>` to fix).                                                                                                                                                                                                                                                           |
| `keychain` | OS credential store via [go-keyring](https://github.com/zalando/go-keyring): macOS Keychain, Linux Secret Service (GNOME Keyring / KWallet over D-Bus), Windows Credential Manager. Service `nexus-cli`, account `ed25519:<absolute key path>` — so every `--key` path has its own entry. Never falls back to a file.                                                                                                                                           |
| `auto`     | If a key file exists at the path, use it (keys are never migrated silently). Otherwise use the keychain, creating the key there. If the keychain is unavailable (no D-Bus/Secret Service on a headless box, access denied, or no answer within 3 s) fall back to a file and print a one-line note on stderr. If **both** a file and a keychain entry exist, refuse to start and ask you to resolve it — a planted key file must not silently take over signing. |

In `auto` mode the keychain is probed on every load (to detect that conflict); set
`NEXUS_KEY_BACKEND=file` to skip it, e.g. on CI.

`--key <path>` (on `dev`, `run`, `mcp serve`, `identity mint`, `keys`) picks an alternate key; the
backend rules apply per path.

## Threat model — what each option actually protects against

The adversary is the AI agent nexus-cli governs: a process running as **your OS user** that may
have file-system and shell access.

- **File backend.** File permissions protect the seed from _other_ users only. Any process
  running as you — including the agent — can read `~/.nexus/ed25519.key` and mint its own
  tokens. Treat this as "no protection against the agent".
- **Keychain backend.** Protects against agents that can read files but cannot (or do not)
  call the credential store. How much more that buys depends on the OS:
  - **macOS:** Keychain items carry an access-control list. Another binary (e.g. `security
find-generic-password` launched by the agent) triggers a user-visible prompt before it can
    read the item. Do not click "Always Allow" for tools the agent can run.
  - **Linux (Secret Service):** once your login keyring is unlocked, _any_ process in your
    session that can talk to D-Bus — including the agent, e.g. with `secret-tool lookup service
nexus-cli` — can read the seed without a prompt. This mainly stops naive file exfiltration
    and keeps the seed out of backups, dotfile repos and `cat ~/.nexus/*`; it is not a security
    boundary against a determined same-user process.
  - **Windows Credential Manager:** readable by any process running as the same user.
- **Strongest option: run the agent as a different OS user, or in a container/VM**, with the
  nexus-cli key (file or keychain) belonging to your user and only the proxy port reachable from
  the agent. Then neither the file nor the keychain is accessible to the agent at all.

Pin the backend once you have migrated: with `NEXUS_KEY_BACKEND=keychain` a key file planted at
the default path is ignored. In `auto` mode such a file causes a conflict error rather than
being used, but an agent that can delete keychain entries could still force a fallback — an
explicit backend avoids that.

The retired-key list (`ed25519.retired.json`, see below) holds public keys only, but it is a
trust anchor (tokens signed by listed keys are accepted), so it is signed by the current
signing key; a list that was edited or re-signed by anything else is rejected at load time.

## Key IDs

Each key's `kid` is its [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint
(base64url SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"…"}`). Minted tokens carry it in the JWT
header; JWKS entries carry it alongside `use: sig` and `alg: EdDSA`. Verifiers select the key by
`kid`; a token without `kid` (minted before this change) is checked against the current key only.

## Commands

```bash
nexus-cli keys show                      # kid, backend, public key, location, retired count
nexus-cli keys jwks                      # JWKS: current key first, then retired keys
nexus-cli keys rotate [--yes]            # new key in the same backend; old public key retired
nexus-cli keys migrate --to keychain     # or --to file
nexus-cli keys prune --older-than 720h   # forget retired keys (their tokens stop verifying)
```

### Rotation

`keys rotate` generates a new key in the same backend and appends the old **public** key, with a
`retired_at` timestamp, to `<key dir>/<key name>.retired.json` (`ed25519.retired.json` for the
default key). Verifiers built from the stored key accept tokens signed by the current key and by
every listed retired key, so in-flight tokens keep working until they expire.

- Running `dev`/`run`/`mcp` processes load keys at start-up — restart them after rotating.
- Downstream services that verify tokens themselves must re-fetch the JWKS
  (`nexus-cli keys jwks`); cache it with a short TTL and refetch on an unknown `kid`.
- Retired keys stay trusted until pruned. Once every token minted before the rotation has
  expired (tokens default to a 15-minute TTL), run `keys prune --older-than <age>`; a pruned
  key's tokens are rejected with "unknown signing key id".
- Rotate immediately if you suspect the seed was read — and prune the old key right away
  (`--older-than 0s`) since a leaked key must not stay trusted.

### Migration

`keys migrate --to keychain|file` copies the seed into the destination, reads it back and
compares, and only then deletes it from the source. A source key file is overwritten (random,
then zeros) before removal; on SSDs and copy-on-write filesystems this is best-effort, so rotate
after migrating if the old file may have been copied. Migration refuses to overwrite a
_different_ key already present in the destination. The retired list is unaffected.
