"""Remote git source — shallow-clone a public URL into a tempdir, scan, clean up.

Only http(s) URLs are accepted, and a strict allowlist of hosts is
enforced. Cloning is shallow (depth=1, single-branch, no tags) and bounded
by a 120-second subprocess timeout plus a partial-clone blob filter
(``--filter=blob:limit``) that refuses to fetch any single blob larger than
``_MAX_BLOB_BYTES``. The scan-time ``max_total_bytes`` setting is applied
later, during the file walk, and does not itself cap the on-disk clone.
Authentication is intentionally not supported in v1 — pass a local clone via
``git_local`` if you need private-repo scanning.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from app.core.code_scanner.sources.base import ScanSource

_HOST_ALLOWLIST = frozenset(
    {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "git.sr.ht",
    }
)
_URL_RE = re.compile(r"^https?://[^\s]+$")

# Per-blob fetch cap. A partial clone refuses to download any single object
# larger than this, so a malicious repo cannot stream gigabytes of one giant
# blob past the depth-1 shallow clone. 10 MiB comfortably covers source files.
_MAX_BLOB_BYTES = 10 * 1024 * 1024


def _validate_url(url: str) -> str:
    url = url.strip()
    if not _URL_RE.match(url):
        raise ValueError("Remote git URL must be http(s).")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host not in _HOST_ALLOWLIST:
        raise ValueError(
            f"Remote git host '{host}' is not in the allowlist. Add support explicitly "
            f"or scan a local clone instead."
        )
    # Drop userinfo to avoid sneaking creds into the URL.
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in URLs are not supported.")
    return url


class RemoteGitSource(ScanSource):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self._tempdir: tempfile.TemporaryDirectory[str] | None = None

    def _prepare(self) -> Path:
        url = _validate_url(self.target)
        if shutil.which("git") is None:
            raise RuntimeError(
                "git binary is required for remote-URL scans. Install git or scan a local clone."
            )
        self._tempdir = tempfile.TemporaryDirectory(prefix="gn-scan-")
        dest = Path(self._tempdir.name) / "repo"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--no-tags",
                    f"--filter=blob:limit={_MAX_BLOB_BYTES}",
                    url,
                    str(dest),
                ],
                check=True,
                capture_output=True,
                timeout=120,
                env=env,
            )
        except FileNotFoundError as error:
            self._tempdir.cleanup()
            self._tempdir = None
            raise RuntimeError("git binary not found on PATH.") from error
        except subprocess.TimeoutExpired as error:
            self._tempdir.cleanup()
            self._tempdir = None
            raise RuntimeError("git clone timed out.") from error
        except subprocess.CalledProcessError as error:
            self._tempdir.cleanup()
            self._tempdir = None
            stderr = (error.stderr or b"").decode("utf-8", errors="replace")[:240]
            raise RuntimeError(f"git clone failed: {stderr}") from error

        self.git_metadata = {
            "remote_url": url,
            "clone_depth": "1",
        }
        return dest

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None
