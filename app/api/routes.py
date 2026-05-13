from fastapi import APIRouter, HTTPException

from app.core.detector import SlopDetector
from app.core.settings import get_settings
from app.core.web_ingest import WebsiteFetchError, fetch_website_text
from app.models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    AnalyzeUrlRequest,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    ContentProfile,
    Dimension,
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


@router.get("/threshold")
def threshold() -> dict[str, float]:
    settings = get_settings()
    return {"alert_threshold": settings.slop_alert_threshold}
