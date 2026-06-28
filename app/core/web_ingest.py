from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Final
from urllib.parse import urljoin, urlparse, urlunparse

from app.core.netguard import ip_is_blocked
from app.core.settings import get_settings

TEXT_CONTENT_TYPES: Final = {
    "text/html",
    "text/plain",
    "application/xhtml+xml",
}
MAX_URL_LENGTH: Final = 2048
MAX_REDIRECTS: Final = 5
ALLOWED_PORTS: Final = {80, 443}
ALLOWED_CONTENT_ENCODINGS: Final = {"", "identity"}
CONTROL_OR_SPACE_RE: Final = re.compile(r"[\x00-\x20\x7f]")
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
_REQUEST_HEADERS: Final = {
    "Accept": "text/html,text/plain,application/xhtml+xml;q=0.9,*/*;q=0.5",
    # Refuse compressed responses so a tiny gzipped payload cannot expand
    # past the configured byte cap during decoding.
    "Accept-Encoding": "identity",
    "User-Agent": "GreyNOC-Slop-Detection/0.1",
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
    redirect_count: int = 0
    redirect_chain: tuple[str, ...] = field(default_factory=tuple)
    extraction_text_length: int = 0
    content_hash: str | None = None
    meta_description: str | None = None
    open_graph_title: str | None = None
    open_graph_description: str | None = None


class ReadableHTMLParser(HTMLParser):
    # Tags whose text content we keep, weighted into the readable
    # extraction. Body text from these is more useful than scattered
    # nav/menu chrome.
    _CONTENT_TAGS = {
        "p", "div", "section", "article", "main", "header", "footer",
        "li", "br", "h1", "h2", "h3", "h4", "h5", "h6",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self._chunks: list[str] = []
        self._title_chunks: list[str] = []
        self.meta_description: str | None = None
        self.open_graph_title: str | None = None
        self.open_graph_description: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"}:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            attr_map = {key.lower(): (value or "") for key, value in attrs}
            content = attr_map.get("content", "").strip()
            if not content:
                return
            name = attr_map.get("name", "").lower()
            prop = attr_map.get("property", "").lower()
            if name == "description" and not self.meta_description:
                self.meta_description = content[:600]
            elif prop == "og:title" and not self.open_graph_title:
                self.open_graph_title = content[:240]
            elif prop == "og:description" and not self.open_graph_description:
                self.open_graph_description = content[:600]
            return
        if tag in self._CONTENT_TAGS:
            self._chunks.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg", "canvas"} and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        if tag in self._CONTENT_TAGS:
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


def normalize_website_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        raise WebsiteFetchError("URL is required.")
    if CONTROL_OR_SPACE_RE.search(cleaned):
        raise WebsiteFetchError("URL cannot contain spaces or control characters.")
    if "\\" in cleaned:
        raise WebsiteFetchError("URL cannot contain backslashes.")
    if len(cleaned) > MAX_URL_LENGTH:
        raise WebsiteFetchError("URL is too long.")

    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    return cleaned


def _resolve_pinned_ip(hostname: str, allow_private_urls: bool) -> str:
    """Resolve ``hostname`` once and return one validated IP to connect to.

    Connecting to the returned IP (rather than re-resolving the hostname at
    socket time) is what closes the DNS-rebinding / TOCTOU window: the address
    we vet here is the exact address we connect to. Rejects the whole host if
    ANY resolved address is non-public, because a rebind can return one good
    and one bad record.
    """
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as error:
            raise WebsiteFetchError(f"Could not resolve host: {hostname}") from error
        addresses = [str(result[4][0]) for result in results]
    if not addresses:
        raise WebsiteFetchError(f"Could not resolve host: {hostname}")
    if not allow_private_urls:
        for address in addresses:
            if ip_is_blocked(ipaddress.ip_address(address)):
                raise WebsiteFetchError(
                    "Private, local, and reserved network URLs are not enabled."
                )
    return addresses[0]


def _read_pinned(
    current_url: str, timeout: float, max_bytes: int
) -> tuple[int, http.client.HTTPResponse, bytes | None]:
    """Open a connection to the pinned IP for ``current_url`` and return the response.

    Returns ``(status, response, body_or_None)``. ``body`` is read (capped) only
    for a final (non-redirect) 2xx/3xx-less response; for redirects the body is
    drained and ``None`` is returned so the caller can follow the Location. The
    socket is pinned to a validated IP so a DNS rebind between validation and
    connect cannot redirect egress to a private/metadata address.
    """
    parsed = urlparse(current_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    pinned_ip = _resolve_pinned_ip(_ascii_hostname(host), allow_private_urls=get_settings().allow_private_urls)

    conn: http.client.HTTPConnection | None = None
    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((pinned_ip, port), timeout=timeout)
        if parsed.scheme == "https":
            # Pin the socket to the validated IP, but keep cert validation / SNI
            # bound to the hostname.
            sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            sock = raw_sock
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock  # bypass conn.connect(), which would re-resolve the name
        raw_sock = None  # ownership transferred to conn
        headers = dict(_REQUEST_HEADERS)
        headers["Host"] = host
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        status = response.status
        if status in _REDIRECT_STATUSES:
            response.read()  # drain so the connection can be closed cleanly
            return status, response, None
        if status >= 400:
            response.read()
            raise WebsiteFetchError(f"Website returned HTTP {status}.")
        body = response.read(max_bytes + 1)
        return status, response, body
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        elif raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


def fetch_website_text(url: str) -> FetchedWebsite:
    settings = get_settings()
    normalized_url = normalize_website_url(url)
    allow_private = settings.allow_private_urls
    current_url = _enforce_url_policy(normalized_url, allow_private)

    redirect_chain: list[str] = []
    seen_urls: set[str] = {current_url}
    redirect_count = 0
    raw = b""
    final_url = current_url
    status_code = 0
    response_headers: http.client.HTTPMessage | None = None

    while True:
        try:
            status, response, body = _read_pinned(
                current_url, settings.web_fetch_timeout_seconds, settings.web_fetch_max_bytes
            )
        except WebsiteFetchError:
            raise
        except (OSError, http.client.HTTPException) as error:
            raise WebsiteFetchError(f"Could not fetch website: {error}") from error

        if status in _REDIRECT_STATUSES:
            location = response.headers.get("Location")
            if not location:
                raise WebsiteFetchError("Website sent a redirect without a destination.")
            redirect_count += 1
            if redirect_count > MAX_REDIRECTS:
                raise WebsiteFetchError("Website redirected too many times.")
            # Re-run full validation on every redirect target so DNS rebinding
            # or cross-protocol bounces are rejected at the same gate — and the
            # next hop is pinned to its own freshly validated IP.
            next_url = _enforce_url_policy(urljoin(current_url, location), allow_private)
            if next_url in seen_urls:
                raise WebsiteFetchError("Website redirected in a loop.")
            seen_urls.add(next_url)
            redirect_chain.append(next_url)
            current_url = next_url
            continue

        response_headers = response.headers
        content_type = response_headers.get_content_type()
        if content_type not in TEXT_CONTENT_TYPES:
            raise WebsiteFetchError(f"Unsupported content type: {content_type}")

        content_encoding = (response_headers.get("Content-Encoding") or "").strip().lower()
        if content_encoding and content_encoding not in ALLOWED_CONTENT_ENCODINGS:
            raise WebsiteFetchError(f"Unsupported content encoding: {content_encoding}")

        announced_length = response_headers.get("Content-Length")
        if announced_length is not None:
            try:
                announced = int(announced_length)
            except ValueError as error:
                raise WebsiteFetchError("Server returned an invalid Content-Length.") from error
            if announced > settings.web_fetch_max_bytes:
                raise WebsiteFetchError("Website response exceeded the configured analysis limit.")

        raw = body or b""
        if len(raw) > settings.web_fetch_max_bytes:
            raise WebsiteFetchError("Website response exceeded the configured analysis limit.")
        final_url = current_url
        status_code = status
        break

    charset = response_headers.get_content_charset() or "utf-8"
    try:
        body_text = raw.decode(charset, errors="replace")
    except LookupError:
        # Unknown charset names land here; fall back to utf-8 to keep the
        # analysis useful instead of aborting the whole request.
        body_text = raw.decode("utf-8", errors="replace")
    body = body_text

    meta_description: str | None = None
    open_graph_title: str | None = None
    open_graph_description: str | None = None
    if content_type in {"text/html", "application/xhtml+xml"}:
        parser = ReadableHTMLParser()
        parser.feed(body)
        text = parser.text
        title = parser.title
        meta_description = parser.meta_description
        open_graph_title = parser.open_graph_title
        open_graph_description = parser.open_graph_description
        # If the body text was thin and we got meaningful OG / meta
        # text, splice it into the extraction so the downstream detector
        # has more signal to work with.
        extras: list[str] = []
        if open_graph_title and open_graph_title not in text:
            extras.append(open_graph_title)
        if open_graph_description and open_graph_description not in text:
            extras.append(open_graph_description)
        if meta_description and meta_description not in text:
            extras.append(meta_description)
        if extras:
            text = (" ".join(extras) + " " + text).strip()
    else:
        text = _clean_text(body)
        title = None

    if not text:
        raise WebsiteFetchError("No readable text was found on the website.")

    return FetchedWebsite(
        requested_url=normalized_url,
        final_url=final_url,
        title=title,
        text=text,
        status_code=status_code,
        content_type=content_type,
        byte_count=len(raw),
        redirect_count=redirect_count,
        redirect_chain=tuple(redirect_chain),
        extraction_text_length=len(text),
        content_hash=hashlib.sha256(raw).hexdigest(),
        meta_description=meta_description,
        open_graph_title=open_graph_title,
        open_graph_description=open_graph_description,
    )


def _enforce_url_policy(url: str, allow_private_urls: bool) -> str:
    """Validate URL safety and return a sanitized form with the host punycoded.

    Returning a sanitized URL forces every later step (request, redirect) to
    use the same hostname we just validated, removing a class of bypasses that
    rely on differences between the URL we checked and the URL we connected to.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise WebsiteFetchError("Only http and https URLs can be analyzed.")
    if not parsed.netloc or not parsed.hostname:
        raise WebsiteFetchError("URL is missing a host.")
    if "\\" in parsed.netloc:
        raise WebsiteFetchError("URL host cannot contain backslashes.")
    if parsed.username or parsed.password:
        raise WebsiteFetchError("URLs with embedded usernames or passwords are not supported.")
    if parsed.netloc.endswith(":"):
        raise WebsiteFetchError("URL contains an invalid port.")
    try:
        port = parsed.port
    except ValueError as error:
        raise WebsiteFetchError("URL contains an invalid port.") from error
    if port is not None and port not in ALLOWED_PORTS:
        raise WebsiteFetchError("Only standard website ports 80 and 443 are supported.")

    hostname = parsed.hostname
    ascii_hostname = _ascii_hostname(hostname)
    if not allow_private_urls and _host_is_private(ascii_hostname):
        raise WebsiteFetchError("Private, local, and reserved network URLs are not enabled.")

    # Rebuild netloc with the ASCII hostname so the connection target matches
    # exactly what we validated. This blocks IDN-homograph payloads from
    # silently re-resolving to a different host during the actual fetch.
    netloc = ascii_hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    sanitized = parsed._replace(netloc=netloc)
    return urlunparse(sanitized)


def _ascii_hostname(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise WebsiteFetchError("URL host is invalid or contains unsupported characters.") from error


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
    # Delegate to the shared SSRF classifier so the website fetcher and the LLM
    # seam stay in lock-step, including transitional IPv6 (6to4 / mapped / Teredo)
    # encodings that smuggle a private IPv4 inside a routable-looking address.
    return ip_is_blocked(address)


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# Backwards-compat alias for callers that imported the underscore-prefixed
# validator from the previous version.
_validate_public_url = _enforce_url_policy
