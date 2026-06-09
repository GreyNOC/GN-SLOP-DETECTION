from typing import Final

from pydantic import BaseModel, Field, field_validator

MAX_TEXT_LENGTH: Final = 200_000
MAX_SOURCE_LENGTH: Final = 256
MAX_URL_LENGTH: Final = 2_048
MAX_BATCH_ITEMS: Final = 25
MAX_MEDIA_FILENAME_LENGTH: Final = 256
MAX_SCAN_TARGET_LENGTH: Final = 4_096


CONTENT_PROFILES: Final = ("general", "soc", "marketing", "academic", "support")


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
    profile: str = Field(
        default="general",
        description="Content profile for scoring tweaks: " + " | ".join(CONTENT_PROFILES),
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
    profile: str = Field(default="general", description="Same profile knob as /analyze.")


class SignalMatch(BaseModel):
    term: str
    excerpt: str
    line: int | None = None


class Signal(BaseModel):
    name: str
    category: str
    weight: float
    count: int
    description: str
    matches: list[SignalMatch] = Field(default_factory=list)


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
    redirect_count: int = 0
    redirect_chain: list[str] = Field(default_factory=list)
    extraction_text_length: int = 0
    content_hash: str | None = None
    meta_description: str | None = None
    open_graph_title: str | None = None
    open_graph_description: str | None = None


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
    content_profile: str = Field(
        default="general",
        description="Profile used for scoring (general, soc, marketing, academic, support).",
    )
    sample_quality: str = Field(
        default="medium",
        description="low | medium | high — small samples get low confidence regardless of score.",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Engine confidence in the composite score (lower for very short inputs).",
    )


class BatchAnalyzeRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(..., min_length=1, max_length=MAX_BATCH_ITEMS)


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]


class MediaFinding(BaseModel):
    marker: str
    confidence: str
    detail: str | None = None
    category: str = Field(
        default="structural",
        description=(
            "provenance | synthetic_generation | editing_transcode | "
            "tamper_smuggling | structural"
        ),
    )


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
    parse_status: str = Field(default="ok", description="ok | unsupported | malformed | parser_error")
    parse_warning: str | None = None


_LLM_ALLOWED_PROVIDERS: Final = ("openai", "anthropic")
_LLM_ALLOWED_MODES: Final = ("off", "verify_findings", "scan_all_files")


class LlmCheckConfig(BaseModel):
    provider: str = Field(..., description="openai or anthropic")
    model: str = Field(..., min_length=1, max_length=128)
    api_key: str = Field(..., min_length=20, max_length=512)
    base_url: str | None = Field(default=None, max_length=2048)
    mode: str = Field(default="off", description="off | verify_findings | scan_all_files")

    @field_validator("provider")
    @classmethod
    def _provider_allowlist(cls, value: str) -> str:
        if value not in _LLM_ALLOWED_PROVIDERS:
            raise ValueError(
                f"provider must be one of {_LLM_ALLOWED_PROVIDERS}, got {value!r}"
            )
        return value

    @field_validator("mode")
    @classmethod
    def _mode_allowlist(cls, value: str) -> str:
        if value not in _LLM_ALLOWED_MODES:
            raise ValueError(f"mode must be one of {_LLM_ALLOWED_MODES}, got {value!r}")
        return value


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
    redacted: bool = False
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
    total_findings: int = 0
    suppressed_count: int = 0
    rule_errors: list[dict[str, str]] = Field(default_factory=list)
    redactions_present: bool = False
