from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Final
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.core.settings import get_settings

TEXT_CONTENT_TYPES: Final = {
    "text/html",
    "text/plain",
    "application/xhtml+xml",
}


class WebsiteFetchError(ValueError):
    """Raised when a website cannot be fetched or converted into text."""


@dataclass(frozen=True)
class FetchedWebsite:
    requested_url: str
    final_url: str
    title: str | None
    text: str
    status_code: int
    content_type: str
    byte_count: int


class ReadableHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self._chunks: list[str] = []
        self._title_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"}:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag in {"p", "div", "section", "article", "header", "footer", "li", "br", "h1", "h2", "h3", "h4"}:
            self._chunks.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"} and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag in {"p", "div", "section", "article", "header", "footer", "li", "h1", "h2", "h3", "h4"}:
            self._chunks.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self._title_chunks.append(data)
        self._chunks.append(data)

    @property
    def title(self) -> str | None:
        title = _clean_text(" ".join(self._title_chunks))
        return title or None

    @property
    def text(self) -> str:
        return _clean_text(" ".join(self._chunks))


def fetch_website_text(url: str) -> FetchedWebsite:
    settings = get_settings()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebsiteFetchError("Only http and https URLs can be analyzed.")
    if not parsed.hostname:
        raise WebsiteFetchError("URL is missing a host.")
    if not settings.allow_private_urls and _host_is_private(parsed.hostname):
        raise WebsiteFetchError("Private, local, and reserved network URLs are not enabled.")

    request = Request(
        url,
        headers={
            "Accept": "text/html,text/plain,application/xhtml+xml;q=0.9,*/*;q=0.5",
            "User-Agent": "GreyNOC-Slop-Detection/0.1",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=settings.web_fetch_timeout_seconds) as response:
            content_type = response.headers.get_content_type()
            if content_type not in TEXT_CONTENT_TYPES:
                raise WebsiteFetchError(f"Unsupported content type: {content_type}")
            charset = response.headers.get_content_charset() or "utf-8"
            raw = response.read(settings.web_fetch_max_bytes + 1)
            if len(raw) > settings.web_fetch_max_bytes:
                raise WebsiteFetchError("Website response exceeded the configured analysis limit.")
            body = raw.decode(charset, errors="replace")
            final_url = response.geturl()
            status_code = response.status
    except HTTPError as error:
        raise WebsiteFetchError(f"Website returned HTTP {error.code}.") from error
    except URLError as error:
        reason = getattr(error, "reason", error)
        raise WebsiteFetchError(f"Could not fetch website: {reason}") from error
    except TimeoutError as error:
        raise WebsiteFetchError("Website fetch timed out.") from error

    if content_type == "text/html" or content_type == "application/xhtml+xml":
        parser = ReadableHTMLParser()
        parser.feed(body)
        text = parser.text
        title = parser.title
    else:
        text = _clean_text(body)
        title = None

    if not text:
        raise WebsiteFetchError("No readable text was found on the website.")

    return FetchedWebsite(
        requested_url=url,
        final_url=final_url,
        title=title,
        text=text,
        status_code=status_code,
        content_type=content_type,
        byte_count=len(raw),
    )


def _host_is_private(hostname: str) -> bool:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as error:
            raise WebsiteFetchError(f"Could not resolve host: {hostname}") from error
        addresses = []
        for result in results:
            sockaddr = result[4]
            addresses.append(ipaddress.ip_address(sockaddr[0]))

    return any(_address_is_private(address) for address in addresses)


def _address_is_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
