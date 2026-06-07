from typing import Final

from pydantic import BaseModel, Field

MAX_TEXT_LENGTH: Final = 200_000
MAX_SOURCE_LENGTH: Final = 256
MAX_URL_LENGTH: Final = 2_048
MAX_BATCH_ITEMS: Final = 25
MAX_MEDIA_FILENAME_LENGTH: Final = 256
MAX_SCAN_TARGET_LENGTH: Final = 4_096


class AnalyzeRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Content to inspect for slop indicators",
    )
    source: str | None = Field(
        default=None,
        max_length=MAX_SOURCE_LENGTH,
        description="Optional source label, file name, or ticket ID",
    )


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=MAX_URL_LENGTH,
        description="Website URL to fetch and inspect. Plain domains like greynoc.com are accepted.",
    )
    source: str | None = Field(
        default=None,
        max_length=MAX_SOURCE_LENGTH,
        description="Optional source label, case ID, or analyst note",
    )


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
    items: list[AnalyzeRequest] = Field(..., min_length=1, max_length=MAX_BATCH_ITEMS)


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]


class MediaFinding(BaseModel):
    marker: str
    confidence: str
    detail: str | None = None


class MediaAnalysisResponse(BaseModel):
    source: str | None = None
    file_name: str | None = None
    format: str
    kind: str
    byte_size: int
    algorithm: str
    score: float = Field(..., ge=0.0, le=1.0)
    risk: str
    has_c2pa_manifest: bool
    has_jumbf_box: bool
    has_xmp_packet: bool
    has_synthid_marker: bool
    trailing_bytes: int
    generative_metadata_keys: list[str]
    tool_fingerprints: list[str]
    findings: list[MediaFinding]
    recommendation: str


class LlmCheckConfig(BaseModel):
    provider: str = Field(..., description="openai or anthropic")
    model: str
    api_key: str
    base_url: str | None = None
    mode: str = Field(default="off", description="off | verify_findings | scan_all_files")


class CodeScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=MAX_SCAN_TARGET_LENGTH)
    target_type: str = Field(default="path", description="path | git_local | git_remote | archive")
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    llm: LlmCheckConfig | None = None


class CodeFindingResponse(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    remediation: str
    llm_verdict: str | None = None
    llm_rationale: str | None = None


class CodeScanResponse(BaseModel):
    target: str
    target_type: str
    algorithm: str
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    elapsed_seconds: float
    findings: list[CodeFindingResponse]
    skipped_examples: list[str]
    git_metadata: dict[str, str]
    score: float = Field(..., ge=0.0, le=1.0)
    risk: str
    recommendation: str
    finding_counts: dict[str, int]
