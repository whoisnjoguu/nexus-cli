import os
import ssl

import pytest

import nexus
from conftest import FakeDaemon, write_discovery


def test_proxy_url_from_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://nexus:a@127.0.0.1:1")
    assert nexus.proxy_url() == "http://nexus:a@127.0.0.1:1"
    monkeypatch.setenv("NEXUS_PROXY_URL", "http://nexus:b@127.0.0.1:2")
    assert nexus.proxy_url() == "http://nexus:b@127.0.0.1:2"


def test_proxy_url_from_discovery(isolated_env, daemon, monkeypatch):
    write_discovery(isolated_env, "x", pid=os.getpid(), addr=daemon.addr, token=daemon.TOKEN, kind="dev",
                    listen=":8075")
    assert nexus.proxy_url() == "http://127.0.0.1:8075"
    assert nexus.proxy_url(token="a/b") == "http://nexus:a%2Fb@127.0.0.1:8075"
    monkeypatch.setenv("NEXUS_TOKEN", "jwt")
    assert nexus.proxy_url() == "http://nexus:jwt@127.0.0.1:8075"


def test_proxy_url_from_status(daemon):
    # An env-configured client has no listen address; it is fetched from /v1/status.
    daemon.listen = "127.0.0.1:9999"
    c = nexus.Client(url=daemon.url, control_token=FakeDaemon.TOKEN, token="t")
    assert nexus.proxy_url(c) == "http://nexus:t@127.0.0.1:9999"


def test_proxy_url_none():
    with pytest.raises(nexus.DaemonNotFoundError):
        nexus.proxy_url()


def test_ca_bundle(monkeypatch):
    assert nexus.ca_bundle() is None
    monkeypatch.setenv("SSL_CERT_FILE", "/c")
    assert nexus.ca_bundle() == "/c"
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/b")
    assert nexus.ca_bundle() == "/b"
    monkeypatch.setenv("NEXUS_CA_BUNDLE", "/a")
    assert nexus.ca_bundle() == "/a"


def test_requests_session(monkeypatch):
    pytest.importorskip("requests")
    monkeypatch.setenv("HTTPS_PROXY", "http://nexus:t@127.0.0.1:8075")
    monkeypatch.setenv("NEXUS_CA_BUNDLE", "/bundle.pem")
    s = nexus.requests_session()
    assert s.proxies == {"http": "http://nexus:t@127.0.0.1:8075", "https": "http://nexus:t@127.0.0.1:8075"}
    assert s.verify == "/bundle.pem"
    s2 = nexus.requests_session(proxy="http://127.0.0.1:1", verify=False)
    assert s2.proxies["https"] == "http://127.0.0.1:1" and s2.verify is False


def _proxy_of(client):
    # httpx keeps one transport per proxy pattern (e.g. "all://").
    for transport in client._mounts.values():
        if transport is not None:
            pool = transport._pool
            return str(pool._proxy_url) if hasattr(pool, "_proxy_url") else repr(pool)
    return None


def test_httpx_clients(monkeypatch, tmp_path):
    httpx = pytest.importorskip("httpx")
    import certifi  # httpx dependency

    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(open(certifi.where(), "rb").read())
    monkeypatch.setenv("NEXUS_PROXY_URL", "http://nexus:t@127.0.0.1:8075")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    seen = {}
    real = ssl.create_default_context

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(ssl, "create_default_context", spy)
    c = nexus.httpx_client(timeout=5)
    assert isinstance(c, httpx.Client)
    assert seen.get("cafile") == str(bundle)
    assert "8075" in (_proxy_of(c) or "")
    c.close()

    import asyncio

    ac = nexus.async_httpx_client()
    assert isinstance(ac, httpx.AsyncClient)
    assert "8075" in (_proxy_of(ac) or "")
    asyncio.run(ac.aclose())
