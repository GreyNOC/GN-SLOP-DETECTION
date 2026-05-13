from fastapi import APIRouter

from app.core.detector import SlopDetector
from app.core.settings import get_settings
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, BatchAnalyzeRequest, BatchAnalyzeResponse, Signal

router = APIRouter(prefix="/api/v1", tags=["analysis"])
detector = SlopDetector()


def to_response(request: AnalyzeRequest) -> AnalyzeResponse:
    result = detector.analyze(request.text)
    return AnalyzeResponse(
        source=request.source,
        score=result.score,
        risk=result.risk,
        word_count=result.word_count,
        signals=[Signal(**signal.__dict__) for signal in result.signals],
        recommendation=result.recommendation,
    )


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return to_response(request)


@router.post("/batch", response_model=BatchAnalyzeResponse)
def batch_analyze(request: BatchAnalyzeRequest) -> BatchAnalyzeResponse:
    return BatchAnalyzeResponse(results=[to_response(item) for item in request.items])


@router.get("/threshold")
def threshold() -> dict[str, float]:
    settings = get_settings()
    return {"alert_threshold": settings.slop_alert_threshold}
