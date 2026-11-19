# 檔案功能：定義去識別預算、覆蓋及展示狀態，獨立於郵件原文與模型自由文字。
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DiagnosticCategory = Literal[
    "core_schema",
    "core_support",
    "presentation",
    "input_policy",
    "input_budget",
    "output_truncated",
    "transport",
    "valid_unknown",
    "completed",
    "unavailable",
]


class ReliabilityContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InputCoverage(ReliabilityContract):
    scope: Literal["normalized_registry"] = "normalized_registry"
    status: Literal["complete", "incomplete", "unavailable"] = "unavailable"
    source_units: int = Field(default=0, ge=0, le=1000000)
    represented_units: int = Field(default=0, ge=0, le=1000000)
    omitted_units: int = Field(default=0, ge=0, le=1000000)
    method: Literal["lossless_catalog", "unavailable"] = "unavailable"

    @model_validator(mode="after")
    def counts_match(self):
        if (
            self.status != "unavailable"
            and self.source_units != self.represented_units + self.omitted_units
        ):
            raise ValueError("COVERAGE_COUNTS_INVALID")
        if self.status == "complete" and self.omitted_units:
            raise ValueError("COVERAGE_COUNTS_INVALID")
        if self.status == "incomplete" and not self.omitted_units:
            raise ValueError("COVERAGE_COUNTS_INVALID")
        return self


class RequestBudget(ReliabilityContract):
    system_bytes: int = Field(ge=0, le=10000000)
    data_bytes: int = Field(ge=0, le=10000000)
    schema_bytes: int = Field(ge=0, le=10000000)
    wrapper_bytes: int = Field(ge=0, le=10000000)
    total_bytes: int = Field(ge=0, le=40000000)
    byte_limit: int = Field(ge=1, le=2000000)
    data_byte_limit: int = Field(ge=1, le=2000000)
    estimated_input_tokens: int = Field(ge=0)
    token_method: Literal["character_heuristic_v1"] = "character_heuristic_v1"
    token_safety_margin: float = Field(default=0.25, ge=0, le=1)
    output_reserve_tokens: int = Field(ge=1, le=16384)
    effective_context_tokens: int | None = Field(default=None, ge=1, le=2000000)
    context_status: Literal["estimated_fit", "estimated_exceeded", "unavailable"] = "unavailable"
    wrapper_method: Literal["chat_completions_serialization_bound_v1"] = (
        "chat_completions_serialization_bound_v1"
    )
    email_bytes: int = Field(default=0, ge=0)
    rules_bytes: int = Field(default=0, ge=0)
    catalog_bytes: int = Field(default=0, ge=0)


class PresentationState(ReliabilityContract):
    source: Literal[
        "deterministic_observations", "deterministic_event_facts", "legacy_model", "unavailable"
    ] = "unavailable"
    status: Literal["complete", "degraded", "legacy", "unavailable"] = "unavailable"
    evidence_complete: bool = False
    reason_codes: list[
        Literal[
            "TEMPLATE_AVAILABLE",
            "TEMPLATE_FAILED",
            "LEGACY_PRESENTATION",
            "CORE_NOT_VALID",
            "EVIDENCE_UNAVAILABLE",
        ]
    ] = Field(default_factory=list, max_length=5)


class HeaderCategoryCount(ReliabilityContract):
    category: Literal["authentication", "routing", "mime", "other"]
    fields: int = Field(ge=0, le=1000000)
    chars: int = Field(ge=0, le=1000000000)
    serialized_bytes: int = Field(ge=0, le=1000000000)


class HeaderProfile(ReliabilityContract):
    status: Literal["complete", "bounded_prefix"]
    parts_examined: int = Field(ge=0, le=1000)
    maximum_depth: int = Field(ge=0, le=50)
    categories: list[HeaderCategoryCount] = Field(max_length=4)


class ResourceDiagnostic(ReliabilityContract):
    category: Literal["input_policy"] = "input_policy"
    metric: Literal[
        "raw_bytes",
        "header_chars",
        "text_chars",
        "mime_parts",
        "mime_depth",
        "url_entities",
        "url_scan_occurrences",
        "html_anchor_occurrences",
        "url_evidence_chars",
        "attachments",
        "unavailable",
    ] = "unavailable"
    observed: int | None = Field(default=None, ge=0, le=1000000000)
    limit: int | None = Field(default=None, ge=0, le=1000000000)
    header_profile: HeaderProfile | None = None


class UsageSnapshot(ReliabilityContract):
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)


class AttemptBudget(ReliabilityContract):
    stage: Literal["a", "b"]
    attempt: int = Field(ge=1, le=30)
    completed: bool
    budget: RequestBudget | None = None
    usage: UsageSnapshot | None = None


class SemanticExtractionState(ReliabilityContract):
    """A's declared state is distinct from source delivery and human fact recall."""

    availability: Literal["recorded", "unavailable"] = "unavailable"
    claimed_status: (
        Literal["extracted", "not_found", "unclear", "unrepresentable", "incomplete"] | None
    ) = None
    semantic_completeness: (
        Literal[
            "complete", "unclear", "unrepresentable", "incomplete", "limit_reached", "not_found"
        ]
        | None
    ) = None
    event_count: int | None = Field(default=None, ge=0, le=12)
    relation_count: int | None = Field(default=None, ge=0, le=12)
    factual_recall: Literal["unavailable"] = "unavailable"


class ReliabilitySummary(ReliabilityContract):
    availability: Literal["recorded", "unavailable"] = "unavailable"
    category: DiagnosticCategory = "unavailable"
    core_status: Literal["valid", "invalid", "not_started", "unavailable"] = "unavailable"
    presentation: PresentationState = Field(default_factory=PresentationState)
    coverage: InputCoverage = Field(default_factory=InputCoverage)
    attempts: list[AttemptBudget] = Field(default_factory=list, max_length=60)
    semantic_extraction: SemanticExtractionState = Field(default_factory=SemanticExtractionState)
    first_pass: Literal["completed", "failed", "not_started", "unavailable"] = "unavailable"
    format_recovery: Literal["disabled"] = "disabled"
