import json
import logging
import os
import time
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.settings import get_settings

logger = logging.getLogger("gn_slop")
if not logger.handlers:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    # Optional rotating log file. Off unless GN_SLOP_LOG_FILE is set so
    # the test suite and CLI runs don't litter the cwd. Electron's
    # backend.log capture (electron/main.js) remains the primary on-disk
    # log; this is a secondary structured log for deeper installs.
    _log_file = os.environ.get("GN_SLOP_LOG_FILE")
    if _log_file:
        rotating = RotatingFileHandler(_log_file, maxBytes=2_000_000, backupCount=3)
        rotating.setFormatter(formatter)
        logger.addHandler(rotating)
logger.setLevel(os.environ.get("GN_SLOP_LOG_LEVEL", "INFO").upper())

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
# Resolve the dashboard HTML path once so a missing file fails fast at
# startup and a serving error doesn't surface as an opaque 500 on every
# user navigation.
DASHBOARD_HTML = (STATIC_DIR / "index.html").resolve()
if not DASHBOARD_HTML.is_file():
    logger.warning("Dashboard HTML missing at expected location: %s", DASHBOARD_HTML)
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
)
DASHBOARD_CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self'",
        "script-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
)
DOCS_PATH = "/docs"
DOCS_HOME_BAR = """
<style>
  .gn-docs-home {
    position: sticky;
    top: 0;
    z-index: 10000;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 24px;
    background: #07080a;
    border-bottom: 1px solid #343a46;
    font-family: Inter, ui-sans-serif, system-ui, -apple-system,
      BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .gn-docs-home a {
    display: inline-flex;
    align-items: center;
    min-height: 34px;
    padding: 0 12px;
    border: 1px solid #4ba3ff;
    color: #f3f5f7;
    background: rgba(75, 163, 255, 0.12);
    text-decoration: none;
    font-weight: 800;
  }
  .gn-docs-home span {
    color: #a7afbd;
    font-size: 0.9rem;
  }
</style>
<div class="gn-docs-home">
  <a href="/">Back to Dashboard</a>
  <span>API Docs</span>
</div>
"""

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="GreyNOC slop detection API for explainable content quality signals.",
    docs_url=None,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)

app.include_router(router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


_rate_buckets: dict[str, deque[float]] = {}
_rate_lock = Lock()


def _client_key(request: Request) -> str:
    client = request.client
    return client.host if client else "unknown"


def _is_rate_limited(client_key: str) -> bool:
    if not settings.rate_limit_enabled or settings.rate_limit_requests <= 0:
        return False
    window = settings.rate_limit_window_seconds
    limit = settings.rate_limit_requests
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(client_key, deque())
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
    return False


_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _trusted_origin_set() -> frozenset[str]:
    raw = settings.extra_trusted_origins
    if not raw:
        return frozenset()
    return frozenset(entry.strip() for entry in raw.split(",") if entry.strip())


def _origin_matches_host(request: Request, header_value: str) -> bool:
    """Return True when the supplied Origin/Referer value is same-origin.

    Same-origin means same scheme + host + port as the request itself.
    For Referer we ignore the path/query parts.
    """
    from urllib.parse import urlparse  # local import: tiny cost, no top-level pollution

    try:
        parsed = urlparse(header_value)
    except Exception:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    if request.url.scheme != parsed.scheme:
        return False
    if request.url.netloc != parsed.netloc:
        return False
    return True


@app.middleware("http")
async def enforce_same_origin(request: Request, call_next):
    """CSRF guard against malicious websites that can reach the loopback port.

    A web page visited in any browser tab can POST to ``http://127.0.0.1:<port>``
    and drive the API — that includes triggering code scans of attacker-
    chosen paths, posting to the BYO-LLM endpoint at the user's cost,
    or sending a multi-GB body. TrustedHostMiddleware doesn't stop this
    (it only checks the Host header, which the browser always sets to
    the loopback address). The browser does include an Origin header on
    cross-origin POSTs, so we use that as the perimeter.

    CLI clients, curl, and server-to-server callers don't send Origin
    or Referer — those are explicitly allowed so we don't break the
    existing surface.
    """
    if not settings.enforce_same_origin:
        return await call_next(request)
    if request.method.upper() not in _STATE_CHANGING_METHODS:
        return await call_next(request)
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if not origin and not referer:
        return await call_next(request)
    trusted = _trusted_origin_set()
    for candidate in (origin, referer):
        if not candidate:
            continue
        if _origin_matches_host(request, candidate):
            return await call_next(request)
        # extra_trusted_origins lets a deployment whitelist a non-loopback origin.
        from urllib.parse import urlparse

        try:
            parsed = urlparse(candidate)
            origin_only = f"{parsed.scheme}://{parsed.netloc}"
            if origin_only in trusted:
                return await call_next(request)
        except Exception:
            pass
    return JSONResponse(
        status_code=403,
        content={
            "detail": (
                "Cross-origin POST blocked. Set ENFORCE_SAME_ORIGIN=false or add "
                "the calling origin to EXTRA_TRUSTED_ORIGINS to allow it."
            )
        },
    )


async def _send_413(send, max_bytes: int) -> None:
    body = json.dumps(
        {"detail": f"Request body exceeds the {max_bytes}-byte cap."}
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class BodyCapMiddleware:
    """Refuse oversized requests before they reach a route handler.

    Implemented as a raw ASGI middleware (not BaseHTTPMiddleware) so the
    byte-counting wrapper is the receive callable the route actually reads
    from. Content-Length is a fast reject; a chunked (Transfer-Encoding:
    chunked) body carries no Content-Length, so the running total is counted
    as the body streams in and the request is aborted once it exceeds the cap.
    Without this, an attacker could POST a multi-GB chunked body to any
    endpoint and force Starlette to buffer it before a route rejects it.
    """

    def __init__(self, app) -> None:  # noqa: ANN001
        self.app = app

    async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = settings.max_request_body_bytes
        if max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        has_content_length = False
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                has_content_length = True
                try:
                    if int(value) > max_bytes:
                        await _send_413(send, max_bytes)
                        return
                except ValueError:
                    pass
                break

        # A Content-Length within the cap bounds the body, so stream it straight
        # through. Only a chunked body (no Content-Length) is unbounded by the
        # header, so buffer it under the cap and replay it to the app. Buffering
        # is itself bounded by max_bytes, and legitimate clients (browsers, curl,
        # httpx file uploads) send Content-Length, so this rare path is cheap.
        if has_content_length:
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        received = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            received += len(message.get("body", b""))
            if received > max_bytes:
                await _send_413(send, max_bytes)
                return
            chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        full_body = b"".join(chunks)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": full_body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    # Read-only and static paths are excluded so an aggressive policy cannot
    # lock an analyst out of the dashboard or health endpoint.
    if request.url.path.startswith(("/health", "/static")):
        return await call_next(request)
    if _is_rate_limited(_client_key(request)):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Slow down and try again shortly."},
        )
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # The Swagger UI page needs CDN access for its bundled scripts; the
    # dashboard does not, so it gets a much tighter CSP.
    if request.url.path == "/" or request.url.path.startswith("/static"):
        response.headers.setdefault("Content-Security-Policy", DASHBOARD_CONTENT_SECURITY_POLICY)
    else:
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    return response


# Registered LAST so it is the OUTERMOST middleware: it must wrap the raw ASGI
# receive directly (a BaseHTTPMiddleware sitting outside it would buffer the
# body first and defeat the streamed byte count).
app.add_middleware(BodyCapMiddleware)


@app.exception_handler(Exception)
async def _log_and_500(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all so uncaught exceptions leave a traceback in the backend log
    instead of vanishing into the void on the user's machine. Production
    builds capture stderr to a file (see electron/main.js), so this
    logger.exception call is what gives us something to look at when a
    user reports an internal server error."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    detail = (
        f"{type(exc).__name__}: {exc}"
        if settings.expose_error_detail
        else "Internal server error. Check the backend log for the traceback."
    )
    return JSONResponse(status_code=500, content={"detail": detail})


@app.get("/", include_in_schema=False)
def dashboard() -> Response:
    if not DASHBOARD_HTML.is_file():
        logger.error("Dashboard HTML not found at %s", DASHBOARD_HTML)
        return HTMLResponse(
            "<h1>Dashboard not installed.</h1>"
            "<p>The packaged dashboard files are missing. Reinstall the app.</p>",
            status_code=500,
        )
    return FileResponse(DASHBOARD_HTML)


@app.get("/docs", include_in_schema=False)
def custom_docs() -> HTMLResponse:
    swagger_response = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{settings.app_name} - Swagger UI",
    )
    body = swagger_response.body
    if isinstance(body, bytes | bytearray | memoryview):
        html = bytes(body).decode("utf-8", errors="replace")
    else:
        html = str(body)
    html = html.replace("<body>", f"<body>{DOCS_HOME_BAR}", 1)
    return HTMLResponse(html)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
