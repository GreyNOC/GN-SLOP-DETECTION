from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.settings import get_settings

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
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


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    return response


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/docs", include_in_schema=False)
def custom_docs() -> HTMLResponse:
    swagger_response = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{settings.app_name} - Swagger UI",
    )
    html = swagger_response.body.decode("utf-8")
    home_bar = """
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
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
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
    html = html.replace("<body>", f"<body>{home_bar}", 1)
    return HTMLResponse(html)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}
