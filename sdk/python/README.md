# Nexus Agent SDK (Python)

Gate AI agent tool calls through [`nexus-cli`](https://github.com/whoisnjoguu/nexus-cli)'s
least-privilege policy, dual-actor identity, and tamper-evident audit log.

The SDK delegates decisions to the `nexus-cli` binary, so a Python agent enforces the same
`nexus.yaml` policy the proxy and MCP gateway use.

## Install

```bash
pip install nexus-agent-sdk          # core
pip install "nexus-agent-sdk[httpx]" # + httpx transport
```

Requires `nexus-cli` on `PATH` and a `nexus.yaml` in the working directory.

## Gate a tool function

```python
from nexus import PolicyGate, guard, DeniedError

gate = PolicyGate()  # uses ./nexus.yaml and the nexus-cli binary

@guard(gate, tool="execute_shell")
def execute_shell(cmd: str) -> str:
    ...

try:
    execute_shell("rm -rf /")
except DeniedError as e:
    print("blocked:", e)
```

## Authorize an arbitrary call

```python
from nexus import PolicyGate, ToolCall

gate = PolicyGate()
decision = gate.authorize(ToolCall(
    method="POST",
    host="api.internal.company.com",
    path="/v1/payouts/execute",
    scopes=["payout:write"],
))
if not decision.allowed:
    raise RuntimeError(decision.reason)
```

## Route HTTP through the proxy

```python
from nexus.httpx_transport import client

def mint_token() -> str:
    ...  # e.g. subprocess to `nexus-cli identity mint ... | parse`

http = client(mint_token, proxy_url="http://127.0.0.1:8075")
http.get("http://api.internal.company.com/v1/claims/123")
```

> Note: `policy test` is stateless. Cross-call **session taint tracking** (read-then-exfiltrate
> detection) is enforced by the long-running `nexus-cli dev` proxy and `mcp serve` gateway.
