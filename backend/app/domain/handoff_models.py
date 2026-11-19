# 檔案功能：定義受控模型觀察、不可變交接與分類欄位，隔離人員說明文字。
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from app.domain.email_models import Contract
from app.domain.explanation_policy import ExplanationAssessment, validate_explanation_reference
from app.domain.reliability_models import InputCoverage

KINDS = (
    "authentication",
    "credential_request",
    "urgency_fear",
    "impersonation",
    "generic_salutation",
    "url_deception",
    "language",
    "analysis_override",
)
Kind = Literal[
    "authentication",
    "credential_request",
    "urgency_fear",
    "impersonation",
    "generic_salutation",
    "url_deception",
    "language",
    "analysis_override",
]
Assessment = Literal["observed", "not_observed", "uncertain", "not_applicable"]
Reason = Literal[
    "CREDENTIAL_REQUEST",
    "URGENCY_FEAR",
    "IMPERSONATION",
    "GENERIC_SALUTATION",
    "URL_DECEPTION",
    "LANGUAGE_ANOMALY",
    "ANALYSIS_OVERRIDE",
    "AUTHENTICATION_UNVERIFIED",
    "NO_RISK_OBSERVED",
    "EVIDENCE_INSUFFICIENT",
    "SIMULATED_ANALYSIS",
]
Uncertainty = Literal[
    "AMBIGUOUS_REQUEST", "AMBIGUOUS_IDENTITY", "AMBIGUOUS_URL", "UNMAPPED_CONTENT", "SIMULATION"
]
EvidenceID = Annotated[str, Field(pattern=r"^e_[0-9a-f]{16}_[0-9]{3}$")]
ObservationID = Annotated[str, Field(pattern=r"^f_[0-9a-f]{16}_[0-9]{3}$")]
Reference = Annotated[str, Field(min_length=1, max_length=120)]


class Observation(Contract):
    kind: Kind
    assessment: Assessment
    evidence_refs: list[Reference] = Field(max_length=100)


class JudgeObservation(Contract):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: ObservationID
    kind: Kind
    assessment: Assessment
    source: Literal["model_a"] = "model_a"
    evidence_ids: tuple[EvidenceID, ...] = Field(max_length=100)


class JudgeInput(Contract):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    contract: Literal["structured_handoff_1", "structured_handoff_2"] = "structured_handoff_1"
    scope_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    observations: tuple[JudgeObservation, ...] = Field(min_length=8, max_length=8)
    program_facts_source: Literal["parser_rules"] = "parser_rules"
    url_count: int = Field(ge=0, le=100000)
    attachment_count: int = Field(ge=0, le=100000)
    url_userinfo_present: bool
    url_ip_host_present: bool
    risky_attachment_extension: bool
    credential_rule_observed: bool
    urgency_rule_observed: bool
    injection_rule_observed: bool
    rules_complete: bool
    rule_count: int = Field(ge=0, le=100000)
    parser_warning_count: int = Field(ge=0, le=100000)
    review_required: bool
    authentication_verification: Literal["not_verified"] = "not_verified"
    coverage: InputCoverage = Field(default_factory=InputCoverage)

    @model_validator(mode="after")
    def bind_scope(self):
        for index, item in enumerate(self.observations, 1):
            if item.kind != KINDS[index - 1] or item.id != f"f_{self.scope_id}_{index:03d}":
                raise ValueError("INVALID_OBSERVATION_SLOT")
            if any(not ref.startswith(f"e_{self.scope_id}_") for ref in item.evidence_ids):
                raise ValueError("INVALID_EVIDENCE_SCOPE")
        return self


class HumanExplanation(Contract):
    category: Literal[
        "authentication", "urgency_fear", "generic_salutation", "url_structure", "language"
    ]
    assessment: ExplanationAssessment
    explanation: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[EvidenceID] = Field(max_length=100)

    @model_validator(mode="after")
    def require_reference(self):
        validate_explanation_reference(self.assessment, self.evidence_refs)
        return self


class ReasonSupport(Contract):
    reason_code: Reason
    observation_id: ObservationID | None
    evidence_refs: list[EvidenceID] = Field(max_length=100)


class SupportViolation(Contract):
    # Fixed taxonomy and counts only: no IDs, raw references, mail text or exception values.
    reason_code: Reason
    condition: Literal[
        "matching_observation_missing",
        "assessment_not_supportive",
        "observation_not_selected",
        "evidence_missing",
        "evidence_not_linked",
        "observation_kind_mismatch",
        "observation_unknown",
        "support_fields_mismatch",
        "duplicate_reason",
    ]
    expected_kind: Kind | None = None
    observation_kind: Kind | None = None
    assessment: Assessment | None = None
    observation_selected: bool = False
    selected_kinds: list[Kind] = Field(default_factory=list, max_length=8)
    referenced_kinds: list[Kind] = Field(default_factory=list, max_length=8)
    available_evidence_count: int = Field(default=0, ge=0, le=100)
    matching_evidence_count: int = Field(default=0, ge=0, le=100)
    invalid_evidence_count: int = Field(default=0, ge=0, le=100)


class ReasonSupportError(ValueError):
    def __init__(self, violations: list[SupportViolation], code="UNSUPPORTED_REASON"):
        self.violations = violations
        super().__init__(code)


class JudgmentProposal(Contract):
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]
    reason_supports: list[ReasonSupport] = Field(min_length=1, max_length=20)
    uncertainty_codes: list[Uncertainty] = Field(max_length=10)
    rationale: str = Field(min_length=1, max_length=2000)
    explanations: list[HumanExplanation] = Field(max_length=10)


class SupportBinding(Contract):
    observation_id: ObservationID | None
    evidence_refs: list[EvidenceID] = Field(max_length=4)


class ReasonSlots(Contract):
    CREDENTIAL_REQUEST: SupportBinding | None
    URGENCY_FEAR: SupportBinding | None
    IMPERSONATION: SupportBinding | None
    GENERIC_SALUTATION: SupportBinding | None
    URL_DECEPTION: SupportBinding | None
    LANGUAGE_ANOMALY: SupportBinding | None
    ANALYSIS_OVERRIDE: SupportBinding | None
    AUTHENTICATION_UNVERIFIED: SupportBinding | None
    NO_RISK_OBSERVED: SupportBinding | None
    EVIDENCE_INSUFFICIENT: SupportBinding | None
    SIMULATED_ANALYSIS: SupportBinding | None


class DecisionCore(Contract):
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]
    reason_slots: ReasonSlots
    uncertainty_codes: list[Uncertainty] = Field(max_length=10)


class CoreResponse(Contract):
    decision: DecisionCore


class StructuredJudgment(Contract):
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]
    reason_codes: list[Reason] = Field(min_length=1, max_length=20)
    supporting_observation_ids: list[ObservationID] = Field(max_length=8)
    evidence_refs: list[EvidenceID] = Field(max_length=100)
    uncertainty_codes: list[Uncertainty] = Field(max_length=10)
    rationale: str = Field(min_length=1, max_length=2000)
    explanations: list[HumanExplanation] = Field(max_length=10)
    # None only for strict flat-format compatibility / historical reading; never inferred.
    reason_supports: list[ReasonSupport] | None = Field(default=None, min_length=1, max_length=20)


class DecodedCore(StructuredJudgment):
    core: DecisionCore
