"""Optional httpx transport that routes agent HTTP through the nexus proxy with a token.

Requires ``httpx``. Import lazily so the core SDK has no hard dependency.
"""

from __future__ import annotations

from typing import Callable, Optional

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "nexus.httpx_transport requires the 'httpx' package") from exc


class NexusTransport(httpx.BaseTransport):
    """Attaches a dual-actor bearer token and forwards through the nexus proxy.

    ``token_source`` is called per request to obtain a fresh short-lived token (e.g. by shelling
    to ``nexus-cli identity mint`` or reading a cached one).
    """

    def __init__(
        self,
        token_source: Callable[[], str],
        proxy_url: str = "http://127.0.0.1:8075",
        base: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self._token_source = token_source
        self._base = base or httpx.HTTPTransport(proxy=proxy_url)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        token = self._token_source()
        request.headers["Authorization"] = f"Bearer {token}"
        return self._base.handle_request(request)


def client(token_source: Callable[[], str], proxy_url: str = "http://127.0.0.1:8075", **kwargs) -> "httpx.Client":
    """Build an ``httpx.Client`` whose traffic is gated by the nexus proxy."""
    return httpx.Client(transport=NexusTransport(token_source, proxy_url), **kwargs)
