# Container image

`ghcr.io/whoisnjoguu/nexus-cli` runs the zero-trust proxy (`nexus-cli dev`) as a sidecar. It is
published for `linux/amd64` and `linux/arm64` on every release tag (`vX.Y.Z`, plus `latest` for
non-prereleases).

| Property    | Value                                                                    |
| ----------- | ------------------------------------------------------------------------ |
| Base        | `gcr.io/distroless/static-debian12:nonroot` (no shell, no package tools) |
| User        | `nonroot` (uid/gid `65532`)                                              |
| Entrypoint  | `/usr/local/bin/nexus-cli`                                               |
| Default cmd | `dev --listen 0.0.0.0:8075`                                              |
| Port        | `8075` (proxy; health at `/_nexus/health`)                               |
| State       | `NEXUS_HOME=/home/nonroot/.nexus` (declared as a volume)                 |
| Environment | `NEXUS_KEY_BACKEND=file`, `NEXUS_NOTIFY=off`                             |

The volume holds the signing key, audit log, replay/one_time/taint state, the CA (if you run
`ca init`) and the control discovery file. Keep it on a named volume so tokens, replay protection
and the audit chain survive restarts.

## Run it

```bash
mkdir -p policy && cp nexus.yaml policy/nexus.yaml

docker volume create nexus-data
docker run -d --name nexus --read-only \
  -p 127.0.0.1:8075:8075 \
  -v nexus-data:/home/nonroot/.nexus \
  -v "$PWD/policy:/etc/nexus:ro" \
  -e NEXUS_POLICY=/etc/nexus/nexus.yaml \
  ghcr.io/whoisnjoguu/nexus-cli:latest
```

- Mount the policy's **directory**, not the single file: editors that save by replacing the file
  break single-file bind mounts, and hot reload would never see the change.
- Without a policy, the built-in safe-tier default applies (reads allowed, writes ask, shell
  denied).
- The root filesystem can be read-only; everything is written under `NEXUS_HOME`.
- Publish the port on `127.0.0.1` unless other machines should reach the proxy. Inside the
  container the proxy binds `0.0.0.0` so that the published port and other containers on the
  same network can reach it; it prints a warning about that at startup.

## Tokens, approvals and the audit log

The signing key lives in the volume, so mint tokens and answer approvals inside the container.
Nobody is logged in there, so pass the human principal with `-u`:

```bash
TOKEN=$(docker exec nexus nexus-cli identity mint -a my-agent -u alice -q)
export HTTP_PROXY="http://agent:$TOKEN@127.0.0.1:8075" HTTPS_PROXY="http://agent:$TOKEN@127.0.0.1:8075"
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"   # curl only reads lowercase http_proxy

docker exec -it nexus nexus-cli approve          # interactive approvals
docker exec nexus nexus-cli approve --list       # or list, then decide by id
docker exec nexus nexus-cli approve <id> --decision once
docker exec nexus nexus-cli audit verify
docker exec nexus nexus-cli doctor
```

Agents in other containers on the same Docker network use the container name as the proxy host,
for example `HTTP_PROXY=http://agent:$TOKEN@nexus:8075`. Set the lowercase variants too: some
clients (curl, for one) read only `http_proxy`. A client that ignores the proxy variables bypasses
nexus entirely; put agents on an internal network whose only way out is the proxy if that matters
(see [docs/threat-model.md](threat-model.md)).

The control API (approvals, `/v1/check`) listens on the container's loopback interface only, so
`approve --web` and the SDK decision API are not reachable from the host. Use `docker exec` as
above.

Do not bind-mount the host's `~/.nexus` (or another `NEXUS_HOME` that host-side `nexus-cli` also
uses) into the container. Host commands cannot reach the container's control API, treat its
discovery file as stale and remove it.

## HTTPS interception

```bash
docker exec nexus nexus-cli ca init
docker restart nexus                                   # --mitm auto turns interception on
docker cp nexus:/home/nonroot/.nexus/ca/ca.crt ./nexus-ca.crt
```

Give agents `nexus-ca.crt` as their trust bundle (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, ...). Without a CA, HTTPS is gated per host via `CONNECT` only.

## Other commands and flags

Arguments after the image name replace the default command:

```bash
docker run --rm ghcr.io/whoisnjoguu/nexus-cli:latest version
docker run -d ... ghcr.io/whoisnjoguu/nexus-cli:latest dev --listen 0.0.0.0:8075 --strict --single-use
```

Keep `--listen 0.0.0.0:<port>` when overriding `dev`; the default `127.0.0.1` would be unreachable
from outside the container.

`docker stop` sends `SIGTERM`; the proxy drains in-flight requests for up to 5 seconds and exits 0.

## Docker Compose

```yaml
services:
  nexus:
    image: ghcr.io/whoisnjoguu/nexus-cli:latest
    read_only: true
    environment:
      NEXUS_POLICY: /etc/nexus/nexus.yaml
    volumes:
      - nexus-data:/home/nonroot/.nexus
      - ./policy:/etc/nexus:ro
    ports:
      - "127.0.0.1:8075:8075"
    networks: [default, agents]

  agent:
    image: your-agent-image
    environment:
      HTTP_PROXY: http://agent:${NEXUS_TOKEN}@nexus:8075
      HTTPS_PROXY: http://agent:${NEXUS_TOKEN}@nexus:8075
      http_proxy: http://agent:${NEXUS_TOKEN}@nexus:8075 # curl ignores HTTP_PROXY
      https_proxy: http://agent:${NEXUS_TOKEN}@nexus:8075
    networks: [agents] # internal: the proxy is the only way out
    depends_on: [nexus]

networks:
  agents:
    internal: true

volumes:
  nexus-data:
```

Mint `NEXUS_TOKEN` once the `nexus` service is up
(`export NEXUS_TOKEN=$(docker compose exec -T nexus nexus-cli identity mint -a my-agent -u alice -q)`)
before starting `agent`. The `agents` network is `internal`, so the agent has no route to the
internet except through the proxy, even if it ignores the proxy variables. The default token lifetime
is 15 minutes (`--ttl` to change it).

## Build it yourself

```bash
make docker                       # nexus-cli:dev for your architecture
make docker DOCKER_ARCH=arm64     # cross-build (no emulation needed)
make docker IMAGE=myorg/nexus:1   # custom tag
```

`make docker` cross-compiles a static binary into `.docker/linux/<arch>/` and builds the same
`Dockerfile` the release uses. Releases build it with GoReleaser (`dockers_v2`); see
[Releasing](../README.md#releasing).
