"""SSRF guard for outbound requests.

A scanner's whole job is to fetch URLs it was handed, and to follow their
redirects. That is exactly the SSRF primitive: a hostile target can answer a
scan with a 3xx to ``169.254.169.254`` (cloud instance metadata) or an internal
address, and a naive fetcher will follow it, capture the response body, and
write those bytes into the report / webhook / Notion push. On a cloud CI runner
with an attached IAM role that is credential theft.

This module decides whether a destination is allowed to be fetched. It is
applied to the initial URL AND re-applied to every redirect hop, because the
first hop can be a perfectly innocent public host that 302s inward.

DNS rebinding: validate_url resolves the host once to decide, but an HTTP client
resolves the name again when it opens the connection, so a record that flips
between the two lookups could pass validation on a public answer and then
connect to a private one. ``PinnedNetworkBackend`` closes that gap at the
transport layer: it resolves the host itself at connect time, rejects any
blocked address, and connects to the exact IP it checked. The TLS layer (SNI and
certificate hostname verification) and the Host header still use the original
hostname, because only the TCP connect target is swapped.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Iterable, List, Optional
from urllib.parse import urlsplit

import httpcore
import httpx

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Hostnames that resolve to a cloud metadata service. Blocking the IPs below
# covers the common case, but these names are worth rejecting by string too, in
# case resolution is intercepted (DNS rebinding / split-horizon).
BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata",
    }
)


class SSRFError(ValueError):
    """A destination was rejected before any request was made."""


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address that must never be fetched.

    Covers loopback, RFC1918 private, link-local (incl. 169.254.0.0/16 which
    holds the 169.254.169.254 metadata endpoint), unique-local IPv6, reserved,
    multicast, and the unspecified address. IPv4-mapped IPv6 (``::ffff:a.b.c.d``)
    is unwrapped first so an attacker can't smuggle a private v4 through a v6
    literal.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _host_matches_allowlist(host: str, allow: List[str]) -> bool:
    """True if host equals, or is a subdomain of, any allowlist entry."""
    host = host.lower().rstrip(".")
    for entry in allow:
        entry = entry.lower().lstrip("*.").rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def validate_url(
    url: str,
    *,
    allow: Optional[List[str]] = None,
    allow_private: bool = False,
) -> None:
    """Raise SSRFError if ``url`` must not be fetched.

    - scheme must be http/https
    - a scope allowlist, when non-empty, is enforced by hostname
    - unless ``allow_private`` is set, every IP the host resolves to must be a
      public address (a host that resolves to *any* blocked IP is rejected —
      the strict choice, so a rebinding record can't sneak one internal answer
      through)
    """
    parts = urlsplit(url)

    if parts.scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"scheme {parts.scheme!r} not allowed (http/https only): {url}")

    host = parts.hostname
    if not host:
        raise SSRFError(f"no host in URL: {url}")

    if host.lower().rstrip(".") in BLOCKED_HOSTNAMES:
        raise SSRFError(f"blocked metadata hostname: {host}")

    if allow:
        if not _host_matches_allowlist(host, allow):
            raise SSRFError(f"host {host!r} is not in the configured scope allowlist")

    if allow_private:
        return

    # Resolve and check every address the host maps to.
    resolve_public(host, parts.port or 0)


def resolve_public(host: str, port: int) -> List[str]:
    """Resolve ``host`` and return its addresses, raising SSRFError if any is blocked.

    The strict choice: a host that resolves to *any* blocked IP is rejected, so a
    rebinding record can't sneak one internal answer through alongside public ones.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"could not resolve host {host!r}: {exc}") from None

    addrs: List[str] = []
    for info in infos:
        addr = str(info[4][0])
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])  # strip zone id
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise SSRFError(
                f"host {host!r} resolves to blocked address {ip} "
                f"(private/loopback/link-local/metadata)"
            )
        addrs.append(addr)
    return addrs


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that connects only to an IP it has just validated.

    Resolution, the blocked-address check, and the TCP connect all happen here in
    one step, so there is no second lookup for a rebinding record to win. Only the
    connect target is replaced: httpcore still passes the original hostname to the
    TLS layer, so SNI and certificate verification are unchanged.
    """

    def __init__(self, *, allow_private: bool = False, inner: Optional[Any] = None) -> None:
        self._allow_private = allow_private
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        if self._allow_private:
            return await self._inner.connect_tcp(
                host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )
        # Off the event loop: getaddrinfo is blocking.
        addrs = await asyncio.to_thread(resolve_public, host, port)
        if not addrs:
            raise SSRFError(f"host {host!r} resolved to no usable address")
        last_exc: Optional[BaseException] = None
        for addr in addrs:
            try:
                return await self._inner.connect_tcp(
                    addr,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except httpcore.ConnectError as exc:
                last_exc = exc  # try the next validated address
        assert last_exc is not None
        raise last_exc

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        raise SSRFError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses ``PinnedNetworkBackend``.

    httpx does not expose a network-backend hook, so the pool it builds is
    swapped for one that does. ``test_ssrf_pinning`` fails loudly if an httpx
    upgrade renames the attribute.
    """

    def __init__(
        self,
        *,
        verify: bool = True,
        allow_private: bool = False,
        limits: Optional[httpx.Limits] = None,
    ) -> None:
        limits = limits or httpx.Limits()
        super().__init__(verify=verify, limits=limits)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify),
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=PinnedNetworkBackend(allow_private=allow_private),
        )
