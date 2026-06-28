"""Shared SSRF address classification for every outbound network seam.

Both the website fetcher (``web_ingest``) and the bring-your-own-LLM adapter
(``code_scanner.llm``) must refuse to connect to private, loopback, link-local,
or otherwise non-public addresses. Historically each had its own copy of the
flag check, and both missed *transitional IPv6 encodings* that smuggle a private
IPv4 inside a routable-looking IPv6 address:

  * **IPv4-mapped** ``::ffff:127.0.0.1`` / ``::ffff:169.254.169.254``
  * **IPv4-compatible** ``::127.0.0.1`` (deprecated but still resolvable)
  * **6to4** ``2002:7f00:0001::`` embeds ``127.0.0.1`` in bits 16-47
  * **Teredo** ``2001:0::`` carries an obfuscated client IPv4 in the low 32 bits

A guard that only checks ``is_private`` on the outer IPv6 address treats all of
these as public and connects straight to the metadata service. This module
decodes the embedded IPv4 and re-checks it, and is the single source of truth
both seams call so they can never drift apart again.
"""

from __future__ import annotations

import ipaddress

_6TO4 = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_V4_COMPATIBLE = ipaddress.ip_network("::/96")


def _flagged(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 hidden inside a transitional IPv6 form, else ``None``."""
    mapped = address.ipv4_mapped
    if mapped is not None:
        return mapped
    if address in _6TO4:
        return ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
    if address in _TEREDO:
        # Teredo client IPv4 is the low 32 bits, bitwise-inverted.
        return ipaddress.IPv4Address((int(address) & 0xFFFFFFFF) ^ 0xFFFFFFFF)
    if address in _V4_COMPATIBLE and int(address) > 1:
        # ::a.b.c.d (skip :: and ::1, already caught by _flagged).
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def ip_is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address an SSRF guard must refuse.

    Refuses private/loopback/link-local/multicast/reserved/unspecified ranges
    directly, and also decodes transitional IPv6 encodings (mapped, compatible,
    6to4, Teredo) and refuses them when the embedded IPv4 is non-public.
    """
    if _flagged(address):
        return True
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None and _flagged(embedded):
            return True
    return False
