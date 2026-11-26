# 檔案功能：定義受限模型輸出、用量與恢復紀錄，以及雙模型階段成功或失敗契約。

"""Phase 3 contracts. A model recommendation is never a final decision."""

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, computed_field, model_validator

from app.analysis.rules.models import RuleRun
from app.domain.analysis_models import AnalysisVersions, Feature, FeatureResult, RiskJudgment
from app.domain.email_models import Contract, ReviewItem
from app.domain.event_models import (
    EventDecisionCore,
    EventExtraction,
    EventHandoff,
    EventSupportViolation,
    ExtractionStatus,
    SemanticCompleteness,
)
from app.domain.explanation_policy import ExplanationAssessment, validate_explanation_reference
from app.domain.handoff_models import (
    DecisionCore,
    JudgeInput,
    Observation,
    StructuredJudgment,
    SupportViolation,
)
from app.domain.reliability_models import DiagnosticCategory, InputCoverage, RequestBudget
from app.domain.stage_failure import StageFailure
from app.domain.versions import LLM_PIPELINE_VERSION, LLM_SCHEMA_VERSION

Text = Annotated[str, Field(min_length=1, max_length=2000)]
Reference = Annotated[str, Field(min_length=1, max_length=120)]
References = Annotated[list[Reference], Field(max_length=100)]
Texts = Annotated[list[Text], Field(max_length=100)]
ProviderLabel = Annotated[
    str, Field(min_length=1, max_length=80, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")
]


def provider_label(value: str) -> str:
    return TypeAdapter(ProviderLabel).validate_python(value.strip() or "custom")


class ExtractedFeature(Feature):
    feature_type: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: Text
    evidence_refs: References = Field(min_length=1)


class FeatureOutput(FeatureResult):
    observations: list[Observation] | None = None
    features: list[ExtractedFeature] = Field(max_length=100)
    suspicious_url_refs: References
    social_engineering_indicators: Texts
    uncertainties: Texts
    scope_limitations: Texts = Field(default_factory=list)


class RiskExplanation(Contract):
    category: Literal[
        "authentication", "urgency_fear", "generic_salutation", "url_structure", "language"
    ]
    assessment: ExplanationAssessment
    explanation: Text
    evidence_refs: References

    @model_validator(mode="after")
    def observed_requires_evidence(self):
        validate_explanation_reference(self.assessment, self.evidence_refs)
        return self


class JudgmentOutput(RiskJudgment):
    rationale: str = Field(default="", max_length=2000)
    explanations: list[RiskExplanation] = Field(default_factory=list, max_length=10)
    reason_codes: list[Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]] = Field(
        max_length=100
    )
    evidence_refs: References
    uncertainties: Texts
    scope_limitations: Texts = Field(default_factory=list)

    @model_validator(mode="after")
    def require_support(self):
        if self.classification != "UNKNOWN" and (not self.evidence_refs or not self.reason_codes):
            raise ValueError("NON_UNKNOWN_REQUIRES_EVIDENCE_AND_REASON")
        if self.classification == "UNKNOWN" and not (self.reason_codes or self.uncertainties):
            raise ValueError("UNKNOWN_REQUIRES_REASON")
        return self


class TokenUsage(Contract):
    input_tokens: int = Field(ge=0, strict=True)
    output_tokens: int = Field(ge=0, strict=True)


class OutputDiagnostic(Contract):
    # Closed codes and top-level contract fields only; never store input values/errors.
    reason: Literal[
        "invalid_response",
        "output_truncated",
        "finish_not_stop",
        "refusal_or_tool_call",
        "invalid_usage",
        "output_token_limit",
        "output_byte_limit",
        "invalid_json",
        "duplicate_json_key",
        "non_finite_json",
        "schema_mismatch",
        "evidence_mismatch",
        "insufficient_support",
        "input_budget_exceeded",
    ]
    fields: list[
        Literal[
            "observations",
            "features",
            "suspicious_url_refs",
            "social_engineering_indicators",
            "uncertainties",
            "scope_limitations",
            "classification",
            "reason_codes",
            "reason_supports",
            "supporting_observation_ids",
            "evidence_refs",
            "uncertainty_codes",
            "rationale",
            "explanations",
            "decision",
            "reason_slots",
            "contract",
            "status",
            "events",
            "relations",
            "inspected_refs",
            "supports",
            "primary_support",
            "additional_supports",
        ]
    ] = Field(default_factory=list, max_length=20)
    constraint: (
        Literal[
            "incomplete_observations",
            "observation_requires_reference",
            "invalid_applicability",
            "observation_requires_evidence",
            "non_unknown_requires_evidence_and_reason",
            "unknown_requires_reason",
            "unsupported_uncertainty",
            "invalid_simulation_claim",
            "invalid_observation",
            "invalid_evidence",
            "unsupported_reason",
            "contradictory_reason",
            "unsupported_safe",
            "unsupported_risk",
            "insufficient_support",
            "invalid_observation_reference",
            "inconsistent_reason_support",
            "invalid_rule_context",
            "invalid_evidence_reference",
            "invalid_event_reference",
            "invalid_extraction_state",
            "unsupported_event_reason",
            "incomplete_semantics",
            "event_limit_exceeded",
            "incomplete_coverage",
            "request_bytes_exceeded",
            "data_bytes_exceeded",
            "estimated_context_exceeded",
        ]
        | None
    ) = None
    support_violations: list[SupportViolation] = Field(default_factory=list, max_length=20)
    event_support_violations: list[EventSupportViolation] = Field(
        default_factory=list, max_length=12
    )
    category: DiagnosticCategory | None = None
    field_paths: list[str] = Field(default_factory=list, max_length=20)
    request_budget: RequestBudget | None = None
    finish_reason: Literal["stop", "length", "other", "unavailable"] = "unavailable"

    @model_validator(mode="after")
    def safe_paths(self):
        from typing import get_args

        from app.domain.event_models import EventReason
        from app.domain.handoff_models import Reason

        allowed = {
            "decision",
            "classification",
            "reason_slots",
            "reason_supports",
            "observation_id",
            "evidence_refs",
            "reason_code",
            "uncertainty_codes",
            "rationale",
            "explanations",
            "assessment",
            "explanation",
            "category",
            "observations",
            "kind",
            "features",
            "description",
            "feature_type",
            "contract",
            "status",
            "events",
            "relations",
            "inspected_refs",
            "action",
            "target",
            "actor",
            "recipient",
            "channel",
            "deadline",
            "consequence",
            "context",
            "polarity",
            "secret_kind",
            "local_id",
            "source_event",
            "target_event",
            "supports",
            "source_id",
            "primary_support",
            "additional_supports",
            "$item",
            *get_args(Reason),
            *get_args(EventReason),
        }
        if any(
            len(path) > 160
            or len(path.split(".")) > 4
            or any(part not in allowed for part in path.split("."))
            for path in self.field_paths
        ):
            raise ValueError("INVALID_DIAGNOSTIC_PATH")
        return self


TimeoutKind = Literal[
    "connect",
    "pool",
    "read",
    "write",
    "unspecified",
    "call_deadline",
    "endpoint_deadline",
    "total_deadline",
]


TransportCategory = Literal[
    "bad_request",
    "authentication",
    "permission",
    "not_found",
    "unprocessable_request",
    "rate_limit",
    "server_error",
    "http_status",
    "connection_error",
    "dns_error",
    "tls_error",
    "protocol_error",
    "timeout",
    "provider_error",
    "unknown",
]
TransportParameter = Literal[
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "response_format",
    "json_schema",
    "model",
    "messages",
    "reasoning_effort",
    "temperature",
    "seed",
    "stream",
    "tools",
    "tool_choice",
    "context_window",
    "num_ctx",
]


class TransportDiagnostic(Contract):
    """Typed metadata only: no exception message, response body, request or headers."""

    category: TransportCategory
    http_status: int | None = Field(default=None, ge=100, le=599, strict=True)
    parameter: TransportParameter | None = None
    timeout_phase: TimeoutKind | None = None


class CallMetadata(Contract):
    stage: Literal["a", "b"]
    attempt: int = Field(ge=1, le=30)
    endpoint_index: int | None = Field(default=None, ge=1, le=10)
    endpoint_attempt: int | None = Field(default=None, ge=1, le=3)
    model_id: str | None = Field(default=None, max_length=200)
    provider: ProviderLabel | None = None
    latency_ms: float = Field(ge=0, allow_inf_nan=False)
    usage: TokenUsage | None = None
    error_code: str | None = None
    diagnostic: OutputDiagnostic | None = None
    request_budget: RequestBudget | None = None
    timeout_kind: TimeoutKind | None = None
    transport_diagnostic: TransportDiagnostic | None = None
    output_token_parameter: Literal["max_completion_tokens", "max_tokens"] | None = None
    request_schema_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_data_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    request_prompt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class RecoveryEvent(Contract):
    stage: Literal["a", "b"]
    after_attempt: int = Field(ge=1, le=30)
    trigger_code: str
    connection_reset: Literal[
        "not_needed", "pending", "succeeded", "failed", "timed_out", "cancelled", "unsupported"
    ] = "not_needed"
    reset_latency_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    retry_delay_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    retry_status: Literal[
        "not_retried", "waiting", "started", "deadline_exceeded", "cancelled", "delay_limit"
    ] = "not_retried"


class LLMRun(Contract):
    phase: Literal[3] = 3
    stage_completed: Literal[True] = True
    final_classification: None = None
    pipeline_version: str = LLM_PIPELINE_VERSION
    schema_version: str = LLM_SCHEMA_VERSION
    provider: ProviderLabel
    # None is retained only for reading historical snapshots, never a live decision.
    simulation: bool | None = None
    framework: Literal["langchain"] = "langchain"
    versions: AnalysisVersions
    content_hash: str
    rules: RuleRun
    analysis_method: Literal[
        "legacy_dual", "structured_dual", "structured_event_dual", "single"
    ] = "legacy_dual"
    handoff: JudgeInput | None = None
    handoff_evidence_map: dict[str, str] = Field(default_factory=dict)
    structured_judgment: StructuredJudgment | None = None
    judgment_format: Literal["core_slots_1", "proposal_v1", "event_facts_core_1"] | None = None
    decision_core: DecisionCore | None = None
    # Distinct wire fields prevent reinterpreting historical eight-slot observations.
    event_extraction: EventExtraction | None = None
    event_handoff: EventHandoff | None = None
    event_evidence_map: dict[str, str] = Field(default_factory=dict)
    event_decision_core: EventDecisionCore | None = None
    coverage: InputCoverage = Field(default_factory=InputCoverage)
    features: FeatureOutput
    judgment: JudgmentOutput
    calls: list[CallMetadata]
    recovery_events: list[RecoveryEvent] = Field(default_factory=list)
    review_items: list[ReviewItem]
    # No price table is configured; unknown usage/cost is never invented as zero.
    estimated_cost: None = None

    @property
    def is_simulation(self) -> bool:
        return self.simulation if self.simulation is not None else self.provider == "fake"

    @computed_field
    @property
    def review_required(self) -> bool:
        return bool(self.review_items)


class LLMFailure(StageFailure):
    phase: Literal[3] = 3
    framework: Literal["langchain"] = "langchain"
    pipeline_version: str = LLM_PIPELINE_VERSION
    schema_version: str = LLM_SCHEMA_VERSION
    failed_stage: Literal["input", "configuration", "a", "b"]
    analysis_method: (
        Literal["legacy_dual", "structured_dual", "structured_event_dual", "single"] | None
    ) = None
    judgment_format: Literal["core_slots_1", "proposal_v1", "event_facts_core_1"] | None = None
    diagnostic: OutputDiagnostic | None = None
    versions: AnalysisVersions | None = None
    calls: list[CallMetadata] = Field(default_factory=list)
    recovery_events: list[RecoveryEvent] = Field(default_factory=list)
    coverage: InputCoverage = Field(default_factory=InputCoverage)
    event_extraction_status: ExtractionStatus | None = None
    event_semantic_completeness: SemanticCompleteness | None = None
    event_count: int | None = Field(default=None, ge=0, le=12)
    relation_count: int | None = Field(default=None, ge=0, le=12)
