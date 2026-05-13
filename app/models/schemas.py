from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Content to inspect for slop indicators")
    source: str | None = Field(default=None, description="Optional source label, file name, or ticket ID")


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        description="Website URL to fetch and inspect. Plain domains like greynoc.com are accepted.",
    )
    source: str | None = Field(default=None, description="Optional source label, case ID, or analyst note")


class Signal(BaseModel):
    name: str
    category: str
    weight: float
    count: int
    description: str


class Dimension(BaseModel):
    name: str
    score: float = Field(..., ge=0.0, le=1.0)
    status: str
    description: str


class ContentProfile(BaseModel):
    algorithm: str
    sentence_count: int
    average_sentence_length: float
    specificity_ratio: float
    evidence_density: float
    repetition_density: float
    link_count: int
    numeric_detail_count: int
    citation_count: int


class WebsiteMetadata(BaseModel):
    requested_url: str
    final_url: str
    title: str | None
    status_code: int
    content_type: str
    byte_count: int


class AnalyzeResponse(BaseModel):
    source: str | None
    input_type: str = Field(default="text", description="text or website")
    score: float = Field(..., ge=0.0, le=1.0)
    risk: str
    word_count: int
    signals: list[Signal]
    dimensions: list[Dimension]
    profile: ContentProfile
    website: WebsiteMetadata | None = None
    recommendation: str


class BatchAnalyzeRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(..., min_length=1, max_length=100)


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
