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

Residual risk (accepted): validate_url resolves the host with getaddrinfo, but
the HTTP client re-resolves the same name when it opens the connection. A DNS
record that flips between the two lookups (classic rebinding) could pass
validation on a public answer and then connect to a private one. Closing this
fully means pinning the validated IP into the connection (connect to the address
we checked, carry the original Host header) rather than re-resolving. That is a
transport-layer change to the fetcher; it is tracked, not yet done. The window is
narrow and the ``--probe`` threat model already assumes an authorised operator,
so this is documented and accepted rather than silently ignored.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlsplit

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
    try:
        infos = socket.getaddrinfo(host, parts.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"could not resolve host {host!r}: {exc}") from None

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
