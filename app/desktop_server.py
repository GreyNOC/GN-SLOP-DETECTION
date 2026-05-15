from __future__ import annotations

import os

import uvicorn

from app.main import app


def main() -> None:
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "8000"))
    log_level = os.environ.get("UVICORN_LOG_LEVEL", "warning")
    uvicorn.run(app, host=host, port=port, log_level=log_level, access_log=False)


if __name__ == "__main__":
    main()
