import tempfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from app.core.code_scanner import (
    Confidence,
    ScanRequest,
    ScanResult,
    ScanTargetType,
    scan_target,
)
from app.core.code_scanner.llm import LlmConfig, scan_whole_file, verify_finding
from app.core.code_scanner.model import Finding, Severity
from app.core.code_scanner.sarif import to_sarif
from app.core.code_scanner.sources import LocalPathSource
from app.core.code_scanner.walker import walk_collect
from app.core.detector import SlopDetector
from app.core.media_detector import analyze_media
from app.core.settings import get_settings
from app.core.web_ingest import WebsiteFetchError, fetch_website_text
from app.models.schemas import (
    MAX_MEDIA_FILENAME_LENGTH,
    MAX_SOURCE_LENGTH,
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeUrlRequest,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    CodeFindingResponse,
    CodeScanRequest,
    CodeScanResponse,
    ContentProfile,
    Dimension,
    MediaAnalysisResponse,
    MediaFinding,
    Signal,
    SignalMatch,
    WebsiteMetadata,
)

router = APIRouter(prefix="/api/v1", tags=["analysis"])
detector = SlopDetector()


def _signal_to_pydantic(signal) -> Signal:
    return Signal(
        name=signal.name,
        category=signal.category,
        weight=signal.weight,
        count=signal.count,
        description=signal.description,
        matches=[
            SignalMatch(term=match.term, excerpt=match.excerpt, line=match.line)
            for match in (signal.matches or ())
        ],
    )


def to_response(
    request: AnalyzeRequest,
    input_type: str = "text",
    website: WebsiteMetadata | None = None,
) -> AnalyzeResponse:
    result = detector.analyze(request.text, profile=getattr(request, "profile", "general"))
    return AnalyzeResponse(
        source=request.source,
        input_type=input_type,
        score=result.score,
        risk=result.risk,
        word_count=result.word_count,
        signals=[_signal_to_pydantic(signal) for signal in result.signals],
        dimensions=[Dimension(**dimension.__dict__) for dimension in result.dimensions],
        profile=ContentProfile(**result.profile.__dict__),
        website=website,
        recommendation=result.recommendation,
        content_profile=result.content_profile,
        sample_quality=result.sample_quality,
        confidence=result.confidence,
    )


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return to_response(request)


@router.post("/analyze-url", response_model=AnalyzeResponse)
def analyze_url(request: AnalyzeUrlRequest) -> AnalyzeResponse:
    try:
        fetched = fetch_website_text(request.url)
    except WebsiteFetchError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    website = WebsiteMetadata(
        requested_url=fetched.requested_url,
        final_url=fetched.final_url,
        title=fetched.title,
        status_code=fetched.status_code,
        content_type=fetched.content_type,
        byte_count=fetched.byte_count,
        redirect_count=fetched.redirect_count,
        redirect_chain=list(fetched.redirect_chain),
        extraction_text_length=fetched.extraction_text_length,
        content_hash=fetched.content_hash,
        meta_description=fetched.meta_description,
        open_graph_title=fetched.open_graph_title,
        open_graph_description=fetched.open_graph_description,
    )
    return to_response(
        AnalyzeRequest(
            text=fetched.text,
            source=request.source or fetched.title or fetched.final_url,
            profile=getattr(request, "profile", "general"),
        ),
        input_type="website",
        website=website,
    )


@router.post("/batch", response_model=BatchAnalyzeResponse)
def batch_analyze(request: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    return BatchAnalyzeResponse(results=[to_response(item) for item in request.items])


@router.post("/analyze-media", response_model=MediaAnalysisResponse)
async def analyze_media_upload(
    file: UploadFile = File(  # noqa: B008 - FastAPI dependency marker, not a default value
        ..., description="Image or video file to scan for provenance markers."
    ),
    source: str | None = Form(default=None),  # noqa: B008 - FastAPI dependency marker
) -> MediaAnalysisResponse:
    settings = get_settings()
    if source is not None and len(source) > MAX_SOURCE_LENGTH:
        raise HTTPException(status_code=422, detail="source label is too long.")

    cap = settings.media_max_bytes
    if cap <= 0:
        raise HTTPException(status_code=500, detail="Media analysis cap is misconfigured.")
    data = await file.read(cap + 1)
    if len(data) > cap:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded media exceeds the {cap}-byte analysis cap.",
        )
    if not data:
        raise HTTPException(status_code=422, detail="Uploaded media is empty.")

    analysis = analyze_media(data)
    file_name = (file.filename or "").strip()
    if len(file_name) > MAX_MEDIA_FILENAME_LENGTH:
        file_name = file_name[: MAX_MEDIA_FILENAME_LENGTH - 1] + "…"
    return MediaAnalysisResponse(
        source=source,
        file_name=file_name or None,
        format=analysis.format.value,
        kind=analysis.kind.value,
        byte_size=analysis.byte_size,
        algorithm=analysis.algorithm,
        score=analysis.score,
        risk=analysis.risk,
        has_c2pa_manifest=analysis.has_c2pa_manifest,
        has_jumbf_box=analysis.has_jumbf_box,
        has_xmp_packet=analysis.has_xmp_packet,
        has_synthid_marker=analysis.has_synthid_marker,
        trailing_bytes=analysis.trailing_bytes,
        generative_metadata_keys=list(analysis.generative_metadata_keys),
        tool_fingerprints=list(analysis.tool_fingerprints),
        findings=[MediaFinding(**asdict(finding)) for finding in analysis.findings],
        recommendation=analysis.recommendation,
        parse_status=analysis.parse_status,
        parse_warning=analysis.parse_warning,
    )


def _finding_to_response(
    finding: Finding,
    *,
    redacted: bool = False,
    llm_verdict: str | None = None,
    llm_rationale: str | None = None,
) -> CodeFindingResponse:
    return CodeFindingResponse(
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        category=finding.category,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        snippet=finding.snippet,
        remediation=finding.remediation,
        redacted=redacted,
        llm_verdict=llm_verdict,
        llm_rationale=llm_rationale,
    )


def _scan_result_to_response(result: ScanResult) -> CodeScanResponse:
    counts: Counter[str] = Counter()
    for finding in result.findings:
        counts[finding.severity.value] += 1
    finding_responses: list[CodeFindingResponse] = []
    for finding in result.findings:
        key = f"{finding.rule_id}@{finding.file_path}:{finding.line_start}"
        redacted = key in result.redacted_findings
        verification = result.llm_verifications.get(key)
        finding_responses.append(
            _finding_to_response(
                finding,
                redacted=redacted,
                llm_verdict=verification.verdict if verification else None,
                llm_rationale=verification.rationale if verification else None,
            )
        )
    return CodeScanResponse(
        target=result.target,
        target_type=result.target_type.value,
        algorithm=result.algorithm,
        files_scanned=result.files_scanned,
        files_skipped=result.files_skipped,
        bytes_scanned=result.bytes_scanned,
        elapsed_seconds=result.elapsed_seconds,
        findings=finding_responses,
        skipped_examples=list(result.skipped_examples),
        git_metadata=dict(result.git_metadata),
        score=result.score,
        risk=result.risk,
        recommendation=result.recommendation,
        finding_counts={severity: counts.get(severity, 0) for severity in (s.value for s in Severity)},
        total_findings=len(result.findings),
        suppressed_count=result.suppressed_count,
        rule_errors=list(result.rule_errors),
        redactions_present=bool(result.redacted_findings),
    )


def _build_scan_request(req: CodeScanRequest) -> ScanRequest:
    try:
        target_type = ScanTargetType(req.target_type)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Unknown target_type: {req.target_type}") from error
    return ScanRequest(
        target=req.target,
        target_type=target_type,
        include_globs=tuple(req.include_globs),
        exclude_globs=tuple(req.exclude_globs),
    )


def _apply_llm(result: ScanResult, llm_payload, request: ScanRequest) -> None:
    if llm_payload is None or llm_payload.mode == "off":
        return
    if llm_payload.provider not in {"openai", "anthropic"}:
        return
    if not llm_payload.api_key:
        return
    config = LlmConfig(
        provider=llm_payload.provider,
        model=llm_payload.model,
        api_key=llm_payload.api_key,
        base_url=llm_payload.base_url or "",
    )

    # Per-finding verification: ask the LLM to second-guess each finding.
    # We only send the snippet stored on the finding itself (already
    # bounded), so users don't accidentally ship a whole file at the
    # bandwidth cost of a one-line match.
    if llm_payload.mode == "verify_findings":
        for finding in result.findings:
            verification = verify_finding(config, finding, finding.snippet)
            key = f"{finding.rule_id}@{finding.file_path}:{finding.line_start}"
            result.llm_verifications[key] = verification

    # Whole-file scan: re-walk just the files that look interesting
    # (have at least one static finding) plus any path the include
    # globs explicitly targeted. We don't blanket every file by default
    # because that's the path that burns user API spend.
    if llm_payload.mode == "scan_all_files":
        try:
            root = LocalPathSource(result.target).root
        except Exception:
            return
        files, _stats = walk_collect(
            root,
            max_bytes_per_file=request.max_bytes_per_file,
            max_total_bytes=request.max_total_bytes,
            max_files=request.max_files,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
        )
        for walked in files:
            entries = scan_whole_file(config, walked.relative_path, walked.text)
            file_lines = walked.text.splitlines()
            for entry in entries:
                severity_value = entry.get("severity", "medium")
                try:
                    severity = Severity(severity_value)
                except ValueError:
                    severity = Severity.MEDIUM
                target_line = max(1, int(entry.get("line", 1)))
                window_start = max(0, target_line - 2)
                window_end = min(len(file_lines), target_line + 1)
                snippet = " | ".join(file_lines[window_start:window_end])[:240]
                result.findings.append(
                    Finding(
                        rule_id="llm.scan",
                        title=entry.get("title", "LLM finding"),
                        description=entry.get("rationale", ""),
                        severity=severity,
                        confidence=Confidence.LOW,
                        category="llm",
                        file_path=walked.relative_path,
                        line_start=target_line,
                        line_end=target_line,
                        snippet=snippet,
                        remediation="LLM finding — verify manually before acting.",
                    )
                )
        # Recompute the composite score with the new findings in.
        result.compute_score()


@router.post("/scan-code", response_model=CodeScanResponse)
def scan_code(request: CodeScanRequest) -> CodeScanResponse:
    scan_request = _build_scan_request(request)
    try:
        result = scan_target(scan_request)
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (ValueError, NotADirectoryError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    _apply_llm(result, request.llm, scan_request)
    return _scan_result_to_response(result)


@router.post("/scan-code/upload", response_model=CodeScanResponse)
async def scan_code_upload(
    file: UploadFile = File(  # noqa: B008
        ..., description="Archive (.zip / .tar.gz / .tgz) of a code tree to scan."
    ),
    include_globs: str | None = Form(  # noqa: B008
        default=None, description="Comma-separated fnmatch globs to restrict the scan."
    ),
    exclude_globs: str | None = Form(default=None),  # noqa: B008
) -> CodeScanResponse:
    suffix = (file.filename or "").lower()
    if not any(suffix.endswith(ext) for ext in (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        raise HTTPException(
            status_code=422,
            detail="Upload must be a .zip / .tar / .tar.gz / .tgz / .tar.bz2 / .tar.xz archive.",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(suffix).suffix) as tmp:
        data = await file.read()
        if not data:
            raise HTTPException(status_code=422, detail="Uploaded archive is empty.")
        tmp.write(data)
        tmp_path = tmp.name

    scan_request = ScanRequest(
        target=tmp_path,
        target_type=ScanTargetType.ARCHIVE,
        include_globs=tuple(include_globs.split(",")) if include_globs else (),
        exclude_globs=tuple(exclude_globs.split(",")) if exclude_globs else (),
    )
    try:
        result = scan_target(scan_request)
    except (FileNotFoundError, ValueError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass

    result.target = file.filename or "archive"
    return _scan_result_to_response(result)


@router.post("/scan-code/sarif")
def scan_code_sarif(request: CodeScanRequest) -> JSONResponse:
    scan_request = _build_scan_request(request)
    try:
        result = scan_target(scan_request)
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (ValueError, NotADirectoryError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return JSONResponse(content=to_sarif(result))


@router.get("/threshold")
def threshold() -> dict[str, float]:
    settings = get_settings()
    return {"alert_threshold": settings.slop_alert_threshold}
