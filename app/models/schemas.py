from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Content to inspect for slop indicators")
    source: str | None = Field(default=None, description="Optional source label, file name, or ticket ID")


class Signal(BaseModel):
    name: str
    weight: float
    count: int
    description: str


class AnalyzeResponse(BaseModel):
    source: str | None
    score: float = Field(..., ge=0.0, le=1.0)
    risk: str
    word_count: int
    signals: list[Signal]
    recommendation: str


class BatchAnalyzeRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(..., min_length=1, max_length=100)


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
