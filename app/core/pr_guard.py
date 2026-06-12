from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardSignal:
    """A concrete, explainable signal found in PR text or changed-code excerpts."""

    name: str
    category: str
    severity: str
    description: str
    evidence: str


_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "prompt_injection_ignore_instructions",
        re.compile(r"\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+instructions\b", re.I),
        "Text attempts to override reviewer or automation instructions.",
    ),
    (
        "prompt_injection_system_prompt",
        re.compile(r"\b(system|developer)\s+prompt\b|\bact\s+as\s+(?:a|an)\b", re.I),
        "Text references system/developer prompts or role-play instructions.",
    ),
    (
        "automation_bypass_request",
        re.compile(r"\b(do\s+not|don't|dont)\s+(flag|detect|report|scan|review)\b", re.I),
        "Text asks automated checks or reviewers not to inspect it.",
    ),
    (
        "hidden_review_instruction",
        re.compile(r"<!--[\s\S]*?(ignore|disregard|do\s+not\s+review|do\s+not\s+flag)[\s\S]*?-->", re.I),
        "Hidden HTML comment contains reviewer/automation steering text.",
    ),
)

_CODE_SLOP_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "placeholder_implementation",
        re.compile(r"(?m)^\s*(pass|\.\.\.|raise\s+NotImplementedError\b|return\s+None\s*(?:#.*)?$)"),
        "slop",
        "Changed code contains placeholder implementation markers.",
    ),
    (
        "silent_exception_swallow",
        re.compile(r"(?ms)except\s+(?:Exception\b|BaseException\b|:).*?\n\s*(?:pass|return\s+(?:None|True|False)|continue)\b"),
        "security",
        "Changed code appears to swallow exceptions without logging or remediation.",
    ),
    (
        "test_disable_marker",
        re.compile(r"\b(?:pytest\.mark\.skip|describe\.skip|it\.skip|test\.skip|xtest|xit)\b", re.I),
        "quality",
        "Changed code disables tests or test blocks.",
    ),
    (
        "type_safety_escape",
        re.compile(r"\b(?:type:\s*ignore|#\s*noqa|pylint:\s*disable|as\s+any|:\s*any\b)", re.I),
        "quality",
        "Changed code suppresses type/lint safety checks.",
    ),
    (
        "dangerous_exec_eval",
        re.compile(r"\b(?:eval|exec)\s*\(|subprocess\.(?:call|run|Popen)\s*\([^\n]*(?:shell\s*=\s*True)", re.I),
        "security",
        "Changed code uses eval/exec or shell execution patterns that need review.",
    ),
)

_SEVERITY_BY_CATEGORY = {
    "prompt": "high",
    "security": "high",
    "slop": "medium",
    "quality": "medium",
}


def scan_pr_text(text: str) -> list[GuardSignal]:
    """Scan PR titles, bodies, comments, or summaries for automation-bypass signals.

    This intentionally avoids claiming authorship. It flags concrete strings that can
    interfere with reviewers, LLM-based triage, or automation.
    """

    content = text or ""
    signals: list[GuardSignal] = []
    for name, pattern, description in _PROMPT_INJECTION_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        signals.append(
            GuardSignal(
                name=name,
                category="prompt",
                severity=_SEVERITY_BY_CATEGORY["prompt"],
                description=description,
                evidence=_safe_excerpt(content, match.start(), match.end()),
            )
        )
    return signals


def scan_changed_code(diff_or_patch: str) -> list[GuardSignal]:
    """Scan changed-code excerpts for objective slop/security signals.

    Feed this a unified diff, a single-file patch, or joined added lines. The function
    looks for concrete failure modes rather than vague AI-authorship indicators.
    """

    content = _added_line_view(diff_or_patch or "")
    signals: list[GuardSignal] = []
    for name, pattern, category, description in _CODE_SLOP_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        signals.append(
            GuardSignal(
                name=name,
                category=category,
                severity=_SEVERITY_BY_CATEGORY[category],
                description=description,
                evidence=_safe_excerpt(content, match.start(), match.end()),
            )
        )
    return signals


def scan_pull_request(title: str, body: str, patch: str = "") -> list[GuardSignal]:
    """Run all lightweight PR hardening checks in one call."""

    return [*scan_pr_text(f"{title}\n\n{body}"), *scan_changed_code(patch)]


def _added_line_view(patch: str) -> str:
    """Return only added lines from a unified diff, or the raw text if not a diff."""

    lines = patch.splitlines()
    if not any(line.startswith(("+++ ", "@@", "+")) for line in lines):
        return patch

    added: list[str] = []
    for line in lines:
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return "\n".join(added)


def _safe_excerpt(text: str, start: int, end: int, radius: int = 80) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    excerpt = re.sub(r"\s+", " ", text[left:right]).strip()
    if left > 0:
        excerpt = "..." + excerpt
    if right < len(text):
        excerpt += "..."
    return excerpt
