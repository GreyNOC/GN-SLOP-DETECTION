import tempfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.core.code_scanner import (
    Confidence,
    ScanRequest,
    ScanResult,
    ScanTargetType,
    scan_target,
)
from app.core.code_scanner.llm import LlmConfig, judge_text, scan_whole_file, verify_finding
from app.core.code_scanner.model import Finding, Severity
from app.core.code_scanner.redaction import redact_text
from app.core.code_scanner.sarif import to_sarif
from app.core.code_scanner.scanner import ScanTargetForbidden
from app.core.code_scanner.sources import LocalPathSource
from app.core.code_scanner.walker import walk_collect
from app.core.detector import SlopDetector
from app.core.media_detector import analyze_media
from app.core.media_vision import fuse_vision_into_analysis, judge_media_image
from app.core.model_detector import select_model_detector
from app.core.settings import get_settings
from app.core.web_ingest import WebsiteFetchError, fetch_website_text
from app.models.schemas import (
    MAX_MEDIA_FILENAME_LENGTH,
    MAX_SOURCE_LENGTH,
    MAX_TEXT_LENGTH,
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
    LlmCheckConfig,
    LlmTextJudgmentResponse,
    MediaAnalysisResponse,
    MediaFinding,
    MediaVisionJudgmentResponse,
    ModelDetectionResponse,
    Signal,
    SignalMatch,
    WebsiteMetadata,
)

router = APIRouter(prefix="/api/v1", tags=["analysis"])
detector = SlopDetector()
# Resolved once at import from SLOP_MODEL_DETECTOR. Default = unavailable
# (no extra installed / env unset), so default responses carry no estimate.
_model_detector = select_model_detector(None)


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


def _maybe_judge_text(request: AnalyzeRequest) -> LlmTextJudgmentResponse | None:
    """Run the optional frontier-model text judge when the caller asks for it.

    Only fires when an ``llm`` block is present with ``mode == "judge_text"``
    and a key. Reuses the same hardened seam as the code scanner.
    """
    cfg = getattr(request, "llm", None)
    if cfg is None or cfg.mode != "judge_text" or not cfg.api_key:
        return None
    config = LlmConfig(
        provider=cfg.provider,
        model=cfg.model,
        api_key=cfg.api_key,
        base_url=cfg.base_url or "",
    )
    judgment = judge_text(config, request.text)
    return LlmTextJudgmentResponse(
        provider=judgment.provider,
        model=judgment.model,
        ai_likelihood=judgment.ai_likelihood,
        slop_verdict=judgment.slop_verdict,
        rationale=judgment.rationale,
    )


def _model_detection_response(result) -> ModelDetectionResponse | None:
    detection = getattr(result, "model_detection", None)
    if detection is None:
        return None
    extra = getattr(detection, "extra", None) or {}
    # Surface whichever raw number is load-bearing for the active backend:
    # single-model perplexity, or the Binoculars cross-perplexity score.
    raw_perplexity = extra.get("perplexity")
    if raw_perplexity is None:
        raw_perplexity = extra.get("binoculars_score")
    return ModelDetectionResponse(
        available=detection.available,
        method=detection.method,
        ai_likelihood=detection.ai_likelihood,
        raw_perplexity=raw_perplexity if isinstance(raw_perplexity, int | float) else None,
        detail=detection.detail,
    )


def to_response(
    request: AnalyzeRequest,
    input_type: str = "text",
    website: WebsiteMetadata | None = None,
) -> AnalyzeResponse:
    # Only run a model detector that is actually available, so default
    # responses (no backend configured) are unchanged.
    detector_arg = _model_detector if _model_detector.is_available() else None
    result = detector.analyze(
        request.text,
        profile=getattr(request, "profile", "general"),
        model_detector=detector_arg,
    )
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
        llm=_maybe_judge_text(request),
        model_detection=_model_detection_response(result),
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
            # A large-but-valid page can exceed the request schema's text cap;
            # clamp it so analysis proceeds on the first MAX_TEXT_LENGTH chars
            # instead of raising a ValidationError that surfaces as a 500.
            text=fetched.text[:MAX_TEXT_LENGTH],
            source=request.source or fetched.title or fetched.final_url,
            profile=getattr(request, "profile", "general"),
        ),
        input_type="website",
        website=website,
    )


@router.post("/batch", response_model=BatchAnalyzeResponse)
def batch_analyze(request: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    return BatchAnalyzeResponse(results=[to_response(item) for item in request.items])


def _maybe_vision_media(
    data: bytes,
    analysis,  # MediaAnalysis — mutated in place by fusion
    *,
    provider: str | None,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
    mode: str,
) -> MediaVisionJudgmentResponse | None:
    """Run the optional frontier vision pass and fuse it into the analysis.

    Opt-in: only fires for mode=='vision' with a provider, model, and key.
    No key => no network. The vision judgment is surfaced verbatim and the
    fused (possibly re-scored) analysis is read by the caller afterwards.
    """
    if mode != "vision":
        return None
    # Run the flat multipart fields through the same validator the JSON
    # surface uses (length caps, provider allowlist, api-key floor) instead
    # of re-implementing a weaker subset inline.
    try:
        checked = LlmCheckConfig(
            provider=provider or "",
            model=model or "",
            api_key=api_key or "",
            base_url=base_url,
            mode="vision",
        )
    except ValidationError as error:
        raise HTTPException(status_code=422, detail=f"Invalid llm_* fields: {error}") from error
    config = LlmConfig(
        provider=checked.provider,
        model=checked.model,
        api_key=checked.api_key,
        base_url=checked.base_url or "",
    )
    judgment = judge_media_image(config, data, analysis.format)
    fuse_vision_into_analysis(analysis, judgment)
    return MediaVisionJudgmentResponse(
        provider=judgment.provider,
        model=judgment.model,
        verdict=judgment.verdict,
        confidence=judgment.confidence,
        ai_artifacts=list(judgment.ai_artifacts),
        rationale=judgment.rationale,
        status=judgment.status,
    )


@router.post("/analyze-media", response_model=MediaAnalysisResponse)
async def analyze_media_upload(
    file: UploadFile = File(  # noqa: B008 - FastAPI dependency marker, not a default value
        ..., description="Image or video file to scan for provenance markers."
    ),
    source: str | None = Form(default=None),  # noqa: B008 - FastAPI dependency marker
    llm_provider: str | None = Form(default=None),  # noqa: B008
    llm_model: str | None = Form(default=None),  # noqa: B008
    llm_api_key: str | None = Form(default=None),  # noqa: B008
    llm_base_url: str | None = Form(default=None),  # noqa: B008
    llm_mode: str = Form(default="off"),  # noqa: B008
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
    # Optional frontier vision pass. Mutates `analysis` in place (appends a
    # finding and re-scores) when an affirmative AI verdict comes back, so
    # the response below reads the fused score/risk/recommendation.
    vision = _maybe_vision_media(
        data,
        analysis,
        provider=llm_provider,
        model=llm_model,
        api_key=llm_api_key,
        base_url=llm_base_url,
        mode=llm_mode,
    )
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
        vision=vision,
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
        pq_readiness=dict(result.pq_readiness),
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
            # Re-resolve via LocalPathSource so a single-file target
            # narrows the LLM pass to that one file the same way the
            # static scan does. Without this, scan_all_files on a
            # single-file PATH target would re-walk the parent dir and
            # ship every sibling to the external provider.
            llm_source = LocalPathSource(request.target)
            root = llm_source.root
        except Exception:
            return
        include_globs = tuple(request.include_globs)
        if llm_source.single_file_relative:
            include_globs = (llm_source.single_file_relative,)
        files, _stats = walk_collect(
            root,
            max_bytes_per_file=request.max_bytes_per_file,
            max_total_bytes=request.max_total_bytes,
            max_files=request.max_files,
            include_globs=include_globs,
            exclude_globs=tuple(request.exclude_globs),
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
                # This snippet is built locally from raw file content, so it
                # bypasses the scanner's redaction pass — redact it here or a
                # hardcoded credential on a flagged line leaks into the report.
                raw_snippet = " | ".join(file_lines[window_start:window_end])[:240]
                snippet, snippet_redacted = redact_text(raw_snippet)
                key = f"llm.scan@{walked.relative_path}:{target_line}"
                if snippet_redacted:
                    result.redacted_findings.add(key)
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
    except ScanTargetForbidden as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
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

    # Stream the upload into the tempfile under a hard cap and abort once it is
    # exceeded, so a chunked (no Content-Length) body cannot write an unbounded
    # archive to disk past the global body-cap middleware.
    cap = get_settings().max_request_body_bytes or (256 * 1024 * 1024)
    written = 0
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(suffix).suffix) as tmp:
        tmp_path = tmp.name
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > cap:
                tmp.close()
                Path(tmp_path).unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded archive exceeds the {cap}-byte cap.",
                )
            tmp.write(chunk)
    if written == 0:
        Path(tmp_path).unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="Uploaded archive is empty.")

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
    except ScanTargetForbidden as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except (ValueError, NotADirectoryError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return JSONResponse(content=to_sarif(result))


@router.get("/threshold")
def threshold() -> dict[str, float]:
    settings = get_settings()
    return {"alert_threshold": settings.slop_alert_threshold}
