"""Bring-your-own-LLM adapter.

The static scanner never makes network calls. This module is the
opt-in seam where a user pastes their own API key, picks a provider
(OpenAI-compatible chat API or Anthropic Messages API), and asks the
LLM to second-guess findings.

The adapter is deliberately conservative:
  * No keys are persisted to disk by this module — the caller hands a
    key in per request.
  * Each prompt sends only the rule context and a bounded snippet of
    code, never the whole repo.
  * Output is forced into a small JSON schema ({verdict, rationale}).
    Anything that doesn't match maps to ``verdict="error"``.
  * Network calls go through stdlib urllib so we don't add a runtime
    dependency on httpx / requests.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Final

from app.core.code_scanner.model import Finding, LlmVerification

# Cap egress so a user holding a finger to the API doesn't accidentally
# spend big.
_MAX_SNIPPET_CHARS: Final = 4_000
_MAX_FILE_CHARS_PER_LLM_FILE_SCAN: Final = 16_000
_REQUEST_TIMEOUT_SECONDS: Final = 30
_ALLOWED_PROVIDERS: Final = frozenset({"openai", "anthropic"})


@dataclass(frozen=True)
class LlmConfig:
    provider: str  # "openai" or "anthropic"
    model: str
    api_key: str
    base_url: str = ""
    max_tokens: int = 512


_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. The user will paste a "
    "static-analysis finding plus the surrounding code. Respond with JSON only, "
    "matching this schema exactly:\n"
    '{"verdict": "likely_true_positive"|"likely_false_positive"|"uncertain", '
    '"rationale": "<one short sentence>"}\n'
    "Do not output anything outside the JSON object."
)


_WHOLE_FILE_SYSTEM_PROMPT = (
    "You are a senior application-security reviewer. The user will paste a "
    "complete source file. Identify any backdoor, RCE primitive, or planted "
    "credential. Respond with JSON only, an array of findings each shaped:\n"
    '{"title": "<short label>", "line": <int>, "rationale": "<one sentence>", '
    '"severity": "low"|"medium"|"high"|"critical"}\n'
    "If nothing is wrong, respond with an empty JSON array."
)


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n…[truncated]"


def _post_json(url: str, body: dict, headers: dict[str, str]) -> dict | str:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
    except urllib.error.HTTPError as error:
        return f"HTTPError {error.code}: {error.reason}"
    except urllib.error.URLError as error:
        return f"URLError: {error.reason}"
    except TimeoutError:
        return "Request timed out."


def _extract_first_json(text: str) -> dict | list | None:
    """Pull the first JSON object or array out of a possibly noisy response.

    LLMs sometimes wrap structured output in markdown fences or
    leading prose. The static scanner contract is "the model can lie
    but it must not crash us", so we extract aggressively but never
    raise.
    """
    if not isinstance(text, str):
        return None
    # Strip markdown fences and surrounding prose.
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text)
    text = re.sub(r"```$", "", text)
    text = text.strip()
    # Find first balanced JSON object or array.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for index, ch in enumerate(text[start:], start=start):
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    chunk = text[start : index + 1]
                    try:
                        return json.loads(chunk)
                    except json.JSONDecodeError:
                        break
    return None


def verify_finding(config: LlmConfig, finding: Finding, code: str) -> LlmVerification:
    """Send a single finding + surrounding code to the user's LLM."""
    if config.provider not in _ALLOWED_PROVIDERS:
        return LlmVerification(
            provider=config.provider,
            model=config.model,
            verdict="error",
            rationale=f"unsupported provider: {config.provider}",
        )
    snippet = _truncate(code, _MAX_SNIPPET_CHARS)
    user_text = (
        f"Rule: {finding.rule_id} — {finding.title}\n"
        f"Severity: {finding.severity.value} / confidence: {finding.confidence.value}\n"
        f"File: {finding.file_path}:{finding.line_start}-{finding.line_end}\n"
        f"Description: {finding.description}\n\n"
        f"Code:\n{snippet}\n"
    )
    response = _call_provider(config, _SYSTEM_PROMPT, user_text)
    parsed = _extract_first_json(response)
    if not isinstance(parsed, dict):
        return LlmVerification(
            provider=config.provider,
            model=config.model,
            verdict="error",
            rationale=str(response)[:240],
        )
    verdict = str(parsed.get("verdict", "uncertain")).lower()
    if verdict not in {"likely_true_positive", "likely_false_positive", "uncertain"}:
        verdict = "uncertain"
    return LlmVerification(
        provider=config.provider,
        model=config.model,
        verdict=verdict,
        rationale=str(parsed.get("rationale", ""))[:240],
    )


def scan_whole_file(config: LlmConfig, file_path: str, code: str) -> list[dict]:
    """Ask the user's LLM to scan a complete file end-to-end.

    Returns a list of `{title, line, rationale, severity}` dicts. The
    caller folds them into the ScanResult findings list.
    """
    if config.provider not in _ALLOWED_PROVIDERS:
        return []
    snippet = _truncate(code, _MAX_FILE_CHARS_PER_LLM_FILE_SCAN)
    user_text = f"Path: {file_path}\n\n{snippet}"
    response = _call_provider(config, _WHOLE_FILE_SYSTEM_PROMPT, user_text)
    parsed = _extract_first_json(response)
    if not isinstance(parsed, list):
        return []
    cleaned: list[dict] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        cleaned.append(
            {
                "title": str(entry.get("title", ""))[:160],
                "line": int(entry.get("line", 1)) if str(entry.get("line", "")).isdigit() else 1,
                "rationale": str(entry.get("rationale", ""))[:240],
                "severity": str(entry.get("severity", "medium")).lower(),
            }
        )
    return cleaned


def _call_provider(config: LlmConfig, system: str, user: str) -> str:
    """Dispatch the configured provider and return raw response text."""
    if config.provider == "openai":
        return _call_openai_compatible(config, system, user)
    if config.provider == "anthropic":
        return _call_anthropic(config, system, user)
    return ""


def _call_openai_compatible(config: LlmConfig, system: str, user: str) -> str:
    base = config.base_url.rstrip("/") if config.base_url else "https://api.openai.com"
    url = f"{base}/v1/chat/completions"
    body = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.0,
        "max_tokens": config.max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }
    response = _post_json(url, body, headers)
    if isinstance(response, str):
        return response
    try:
        return response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(response)[:240]


def _call_anthropic(config: LlmConfig, system: str, user: str) -> str:
    base = config.base_url.rstrip("/") if config.base_url else "https://api.anthropic.com"
    url = f"{base}/v1/messages"
    body = {
        "model": config.model,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "max_tokens": config.max_tokens,
        "temperature": 0.0,
    }
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    response = _post_json(url, body, headers)
    if isinstance(response, str):
        return response
    try:
        return response["content"][0]["text"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(response)[:240]
