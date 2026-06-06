from dataclasses import asdict

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

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
    ContentProfile,
    Dimension,
    MediaAnalysisResponse,
    MediaFinding,
    Signal,
    WebsiteMetadata,
)

router = APIRouter(prefix="/api/v1", tags=["analysis"])
detector = SlopDetector()


def to_response(
    request: AnalyzeRequest,
    input_type: str = "text",
    website: WebsiteMetadata | None = None,
) -> AnalyzeResponse:
    result = detector.analyze(request.text)
    return AnalyzeResponse(
        source=request.source,
        input_type=input_type,
        score=result.score,
        risk=result.risk,
        word_count=result.word_count,
        signals=[Signal(**signal.__dict__) for signal in result.signals],
        dimensions=[Dimension(**dimension.__dict__) for dimension in result.dimensions],
        profile=ContentProfile(**result.profile.__dict__),
        website=website,
        recommendation=result.recommendation,
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
    )
    return to_response(
        AnalyzeRequest(text=fetched.text, source=request.source or fetched.title or fetched.final_url),
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

    # Read one byte past the configured cap so we can distinguish "exactly
    # at the limit" from "exceeds the limit" without holding two copies in
    # memory. UploadFile is a SpooledTemporaryFile so this is safe.
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
    )


@router.get("/threshold")
def threshold() -> dict[str, float]:
    settings = get_settings()
    return {"alert_threshold": settings.slop_alert_threshold}
