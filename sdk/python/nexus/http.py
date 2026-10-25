"""Helpers that point ``requests``/``httpx`` at the nexus proxy and trust its MITM CA.

``nexus-cli run`` already exports ``HTTP(S)_PROXY``/``NEXUS_PROXY_URL`` (with the agent's token
as the proxy password) and, with TLS interception, ``SSL_CERT_FILE``/``REQUESTS_CA_BUNDLE``. These
helpers read the same variables, so code works identically inside and outside ``run``. Outside
``run`` the proxy address comes from the discovered control endpoint's ``listen`` address plus
a token you pass (or ``NEXUS_TOKEN``).
"""

from __future__ import annotations

import inspect
import os
import ssl
from typing import TYPE_CHECKING, Any, Optional, Union
from urllib.parse import quote

from ._discovery import ENV_PROXY_URL, ControlInfo
from ._types import DaemonNotFoundError, NexusError
from .client import Client, env_token

if TYPE_CHECKING:  # pragma: no cover
    import httpx
    import requests

ENV_CA_BUNDLE = "NEXUS_CA_BUNDLE"
_PROXY_ENV = (ENV_PROXY_URL, "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
_CA_ENV = (ENV_CA_BUNDLE, "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")


def _info_of(source: Union[Client, ControlInfo, None]) -> Optional[ControlInfo]:
    if isinstance(source, Client):
        return source.info
    return source


def proxy_url(client: Union[Client, ControlInfo, None] = None, token: Optional[str] = None) -> str:
    """The proxy URL agent HTTP should use.

    ``NEXUS_PROXY_URL``, then ``HTTPS_PROXY``/``HTTP_PROXY`` (as set by ``nexus-cli run``); else
    ``http://nexus:<token>@<listen>`` from the control endpoint (``client`` or discovered), where
    ``token`` defaults to the client's token, else ``NEXUS_TOKEN``. When ``client`` is given the
    proxy environment variables are not consulted. Raises :class:`DaemonNotFoundError` if no proxy
    address is known.
    """
    if client is None:
        for k in _PROXY_ENV:
            v = os.environ.get(k, "").strip()
            if v:
                return v
    listen = ""
    try:
        if client is None:
            client = Client()
        info = _info_of(client)
        listen = info.listen if info else ""
        if not listen and isinstance(client, Client):
            listen = client.status().listen
    except NexusError:
        listen = ""
    if not listen:
        raise DaemonNotFoundError("no nexus proxy address: set NEXUS_PROXY_URL/HTTPS_PROXY or start `nexus-cli dev`")
    host, _, port = listen.rpartition(":")
    if host in ("", "0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    if token is None:
        token = client.token if isinstance(client, Client) and client.token else env_token()
    tok = token
    auth = f"nexus:{quote(tok, safe='')}@" if tok else ""
    return f"http://{auth}{host}:{port}"


def ca_bundle() -> Optional[str]:
    """CA bundle that trusts the nexus MITM CA: ``NEXUS_CA_BUNDLE``, ``REQUESTS_CA_BUNDLE`` or ``SSL_CERT_FILE``."""
    for k in _CA_ENV:
        v = os.environ.get(k, "").strip()
        if v:
            return v
    return None


def _verify(verify: Union[bool, str, None]) -> Union[bool, str]:
    if verify is None:
        return ca_bundle() or True
    return verify


def requests_session(
    client: Union[Client, ControlInfo, None] = None,
    *,
    token: Optional[str] = None,
    proxy: Optional[str] = None,
    verify: Union[bool, str, None] = None,
) -> "requests.Session":
    """A ``requests.Session`` whose HTTP and HTTPS traffic goes through the nexus proxy.

    ``proxy`` defaults to :func:`proxy_url`; ``verify`` to :func:`ca_bundle` (else system CAs).
    Requires the ``requests`` extra.
    """
    try:
        import requests
    except ImportError as exc:  # pragma: no cover
        raise ImportError("nexus.requests_session requires 'requests' (pip install 'nexus-agent-sdk[requests]')") from exc
    p = proxy or proxy_url(client, token)
    s = requests.Session()
    s.proxies = {"http": p, "https": p}
    s.verify = _verify(verify)
    return s


def _httpx_kwargs(client: Any, token: Optional[str], proxy: Optional[str], verify: Union[bool, str, None], kwargs: dict) -> dict:
    import httpx

    p = proxy or proxy_url(client, token)
    v = _verify(verify)
    if isinstance(v, str):
        v = ssl.create_default_context(cafile=v)  # type: ignore[assignment]
    kwargs.setdefault("verify", v)
    params = inspect.signature(httpx.Client.__init__).parameters
    if "proxy" in params:
        kwargs.setdefault("proxy", p)
    else:  # pragma: no cover - httpx < 0.26
        kwargs.setdefault("proxies", p)
    return kwargs


def httpx_client(
    client: Union[Client, ControlInfo, None] = None,
    *,
    token: Optional[str] = None,
    proxy: Optional[str] = None,
    verify: Union[bool, str, None] = None,
    **kwargs: Any,
) -> "httpx.Client":
    """An ``httpx.Client`` routed through the nexus proxy (see :func:`requests_session`)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError("nexus.httpx_client requires 'httpx' (pip install 'nexus-agent-sdk[httpx]')") from exc
    return httpx.Client(**_httpx_kwargs(client, token, proxy, verify, kwargs))


def async_httpx_client(
    client: Union[Client, ControlInfo, None] = None,
    *,
    token: Optional[str] = None,
    proxy: Optional[str] = None,
    verify: Union[bool, str, None] = None,
    **kwargs: Any,
) -> "httpx.AsyncClient":
    """An ``httpx.AsyncClient`` routed through the nexus proxy (see :func:`requests_session`)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise ImportError("nexus.async_httpx_client requires 'httpx' (pip install 'nexus-agent-sdk[httpx]')") from exc
    return httpx.AsyncClient(**_httpx_kwargs(client, token, proxy, verify, kwargs))
