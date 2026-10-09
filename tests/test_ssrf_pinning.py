"""DNS-rebinding TOCTOU: the connection must go to the IP the guard validated.

validate_url resolves a host once; the HTTP client used to resolve it again at
connect time. These tests drive a real Fetcher through the pinned transport with
the TCP layer faked, so what the transport would have connected to is observable.
"""

import asyncio
import socket

import httpcore
import pytest

from aegisaudit.config import AegisConfig, LimitsConfig, ScopeConfig
from aegisaudit.fetcher import Fetcher
from aegisaudit.ssrf import PinnedNetworkBackend, PinnedTransport, SSRFError

PUBLIC = "93.184.216.34"
PRIVATE = "169.254.169.254"

RESPONSE = b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 2\r\n\r\nok"


def addrinfo(ip: str, port: int):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class Recorder:
    """Stands in for the TCP layer: records connect targets and TLS hostnames."""

    def __init__(self) -> None:
        self.connect_hosts: list[str] = []
        self.tls_hostnames: list[str | None] = []
        self.requests: list[bytes] = []

    def patch(self, monkeypatch) -> None:
        recorder = self
        mock = httpcore.AsyncMockBackend([RESPONSE])

        async def connect_tcp(
            self_, host, port, timeout=None, local_address=None, socket_options=None
        ):
            recorder.connect_hosts.append(host)
            stream = await mock.connect_tcp(host, port)
            inner_start_tls = stream.start_tls

            async def start_tls(ssl_context, server_hostname=None, timeout=None):
                recorder.tls_hostnames.append(server_hostname)
                return await inner_start_tls(ssl_context, server_hostname, timeout)

            stream.start_tls = start_tls
            inner_write = stream.write

            async def write(buffer, timeout=None):
                recorder.requests.append(bytes(buffer))
                return await inner_write(buffer, timeout)

            stream.write = write
            return stream

        monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", connect_tcp)


def make_fetcher(**kwargs) -> Fetcher:
    cfg = AegisConfig()
    cfg.limits = LimitsConfig(rate_per_sec=100, **kwargs.pop("limits", {}))
    cfg.scope = ScopeConfig(**kwargs)
    return Fetcher(cfg)


def fetch(fetcher: Fetcher, url: str):
    async def run():
        try:
            return await fetcher.fetch(url)
        finally:
            await fetcher.close()

    return asyncio.run(run())


def test_pinned_transport_replaces_the_pool_backend():
    """Guards the one private attribute PinnedTransport relies on."""
    transport = PinnedTransport()
    assert isinstance(transport._pool, httpcore.AsyncConnectionPool)
    assert isinstance(transport._pool._network_backend, PinnedNetworkBackend)


def test_rebind_to_private_is_blocked_at_connect(monkeypatch):
    """validate_url sees a public answer; the connect-time lookup says private."""
    answers = iter([PUBLIC, PRIVATE])
    monkeypatch.setattr(
        "aegisaudit.ssrf.socket.getaddrinfo",
        lambda host, port, **_: addrinfo(next(answers), port),
    )
    rec = Recorder()
    rec.patch(monkeypatch)

    artifact = fetch(make_fetcher(), "http://rebind.test/")

    assert artifact is None
    assert rec.connect_hosts == []  # the private address was never connected to


def test_connects_to_the_validated_ip_not_the_hostname(monkeypatch):
    lookups: list[str] = []

    def resolve(host, port, **_):
        lookups.append(host)
        return addrinfo(PUBLIC, port)

    monkeypatch.setattr("aegisaudit.ssrf.socket.getaddrinfo", resolve)
    rec = Recorder()
    rec.patch(monkeypatch)

    artifact = fetch(make_fetcher(), "http://example.com/")

    assert artifact is not None and artifact.status_code == 200
    assert rec.connect_hosts == [PUBLIC]
    # Host header still names the site, so virtual hosts keep working.
    assert b"host: example.com" in rec.requests[0].lower()


@pytest.mark.parametrize("insecure", [False, True])
def test_tls_hostname_stays_the_original_while_ip_is_pinned(monkeypatch, insecure):
    monkeypatch.setattr(
        "aegisaudit.ssrf.socket.getaddrinfo", lambda host, port, **_: addrinfo(PUBLIC, port)
    )
    rec = Recorder()
    rec.patch(monkeypatch)

    artifact = fetch(make_fetcher(limits={"insecure": insecure}), "https://example.com/")

    assert artifact is not None
    assert rec.connect_hosts == [PUBLIC]
    # SNI and certificate verification use the hostname, not the pinned IP.
    assert rec.tls_hostnames == ["example.com"]


def test_insecure_still_verifies_when_not_set():
    """`insecure` toggles certificate verification and nothing else."""
    strict = PinnedTransport(verify=True)._pool._ssl_context
    loose = PinnedTransport(verify=False)._pool._ssl_context
    import ssl

    assert strict.verify_mode == ssl.CERT_REQUIRED
    assert strict.check_hostname is True
    assert loose.verify_mode == ssl.CERT_NONE


def test_allow_private_skips_the_address_check(monkeypatch):
    monkeypatch.setattr(
        "aegisaudit.ssrf.socket.getaddrinfo", lambda host, port, **_: addrinfo("127.0.0.1", port)
    )
    rec = Recorder()
    rec.patch(monkeypatch)

    artifact = fetch(make_fetcher(allow_private=True), "http://localhost/")

    assert artifact is not None
    assert rec.connect_hosts == ["localhost"]


def test_backend_rejects_blocked_address_directly(monkeypatch):
    monkeypatch.setattr(
        "aegisaudit.ssrf.socket.getaddrinfo", lambda host, port, **_: addrinfo(PRIVATE, port)
    )
    backend = PinnedNetworkBackend()
    with pytest.raises(SSRFError):
        asyncio.run(backend.connect_tcp("evil.test", 80))
