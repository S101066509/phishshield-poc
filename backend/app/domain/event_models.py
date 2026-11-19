# 檔案功能：定義有限語意事件、封閉交接與具來源綁定的分類核心，保留舊八槽契約原義。
"""Event facts are model extraction claims, never trusted authentication or verdicts."""

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from app.domain.email_models import Contract
from app.domain.reliability_models import InputCoverage

MAX_EVENTS = 12
MAX_RELATIONS = 12
MAX_EVENT_REFS = 4
MAX_SIGNALS = 200
EventAction = Literal[
    "login",
    "verify_account",
    "provide_secret",
    "grant_access",
    "view_document",
    "download",
    "execute",
    "enable_macros",
    "install",
    "pay",
    "transfer_money",
    "call_back",
    "change_password",
    "analysis_manipulation",
    "other",
]
EventTarget = Literal[
    "account",
    "authentication_secret",
    "money",
    "document",
    "software",
    "analysis_policy",
    "other",
    "unspecified",
]
Participant = Literal["sender", "recipient", "third_party", "unspecified"]
Channel = Literal[
    "mail_link",
    "attachment",
    "reply",
    "phone",
    "claimed_existing_entry",
    "unspecified",
    "unclear",
]
Deadline = Literal["none", "immediate", "within_day", "within_week", "later", "unclear"]
Consequence = Literal[
    "none",
    "account_disabled",
    "financial_loss",
    "data_loss",
    "service_interruption",
    "unclear",
]
EventContext = Literal[
    "direct_request",
    "reported",
    "quoted_example",
    "security_education",
    "notification",
    "unclear",
]
Polarity = Literal["affirmed", "negated", "unclear"]
SecretKind = Literal[
    "password",
    "otp",
    "recovery_code",
    "payment_secret",
    "unspecified",
    "not_applicable",
]
RelationKind = Literal["prerequisite_for", "consequence_of", "refers_to", "follows"]
ExtractionStatus = Literal["extracted", "not_found", "unclear", "unrepresentable", "incomplete"]
SemanticCompleteness = Literal[
    "complete",
    "not_found",
    "unclear",
    "unrepresentable",
    "incomplete",
    "limit_reached",
]
LocalIndex = Annotated[int, Field(ge=0, le=MAX_EVENTS - 1, strict=True)]
Reference = Annotated[str, Field(min_length=1, max_length=120)]
EvidenceID = Annotated[str, Field(pattern=r"^e_[0-9a-f]{16}_[0-9]{3}$")]
SourceID = Annotated[str, Field(pattern=r"^[vrs]_[0-9a-f]{16}_[0-9]{3}$")]
Refs = Annotated[list[Reference], Field(min_length=1, max_length=MAX_EVENT_REFS)]
EventReason = Literal[
    "ACCOUNT_ACCESS_REQUEST",
    "SECRET_DISCLOSURE_REQUEST",
    "EXECUTION_REQUEST",
    "PAYMENT_REQUEST",
    "COERCIVE_ACTION_REQUEST",
    "LINKED_EXECUTION_REQUEST",
    "ANALYSIS_MANIPULATION",
    "URL_DECEPTION",
    "PROGRAM_RULE_MATCH",
    "NO_RISK_FACTS",
    "EVIDENCE_INSUFFICIENT",
    "SIMULATED_ANALYSIS",
]
EventUncertainty = Literal[
    "SEMANTIC_INCOMPLETE",
    "CONTEXT_AMBIGUOUS",
    "UNREPRESENTED_CONTENT",
    "SOURCE_INCOMPLETE",
    "PROGRAM_REVIEW",
    "SIMULATION",
]
SignalKind = Literal[
    "url_display_mismatch",
    "url_userinfo",
    "url_ip_host",
    "credential_pattern",
    "urgency_pattern",
    "attachment_extension",
    "analysis_manipulation",
    "sender_reply_mismatch",
    "short_url",
    "redirect_parameter",
]


class EventContract(Contract):
    model_config = ConfigDict(extra="forbid", strict=True)


class EventAttributes(EventContract):
    action: EventAction
    target: EventTarget
    actor: Participant
    recipient: Participant
    channel: Channel
    deadline: Deadline
    consequence: Consequence
    context: EventContext
    polarity: Polarity
    secret_kind: SecretKind


class ExtractedEvent(EventAttributes):
    local_id: LocalIndex
    evidence_refs: Refs


class ExtractedRelation(EventContract):
    source_event: LocalIndex
    target_event: LocalIndex
    kind: RelationKind
    evidence_refs: Refs


class EventExtraction(EventContract):
    contract: Literal["event_extraction_1"]
    status: ExtractionStatus
    events: list[ExtractedEvent] = Field(max_length=MAX_EVENTS)
    relations: list[ExtractedRelation] = Field(max_length=MAX_RELATIONS)
    inspected_refs: Refs

    @model_validator(mode="after")
    def valid_structure(self):
        identifiers = [event.local_id for event in self.events]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("INVALID_EVENT_REFERENCE")
        if self.status == "extracted" and not self.events:
            raise ValueError("INVALID_EXTRACTION_STATE")
        if self.status == "not_found" and (self.events or self.relations):
            raise ValueError("INVALID_EXTRACTION_STATE")
        for relation in self.relations:
            if (
                relation.source_event not in identifiers
                or relation.target_event not in identifiers
                or relation.source_event == relation.target_event
            ):
                raise ValueError("INVALID_EVENT_REFERENCE")
        return self

    @property
    def evidence_refs(self) -> list[str]:
        return sorted(
            set(self.inspected_refs).union(
                *(event.evidence_refs for event in self.events),
                *(relation.evidence_refs for relation in self.relations),
            )
        )

    @property
    def explanations(self) -> list:
        return []


class ProjectedEvent(EventAttributes):
    id: SourceID
    source: Literal["model_a_extraction"] = "model_a_extraction"
    evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=MAX_EVENT_REFS)


class ProjectedRelation(EventContract):
    id: SourceID
    source: Literal["model_a_extraction"] = "model_a_extraction"
    source_event: SourceID
    target_event: SourceID
    kind: RelationKind
    evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=MAX_EVENT_REFS)


class ProgramSignal(EventContract):
    id: SourceID
    source: Literal["parser_rules"] = "parser_rules"
    kind: SignalKind
    evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=MAX_EVENT_REFS)


class EventHandoff(EventContract):
    contract: Literal["event_handoff_1"] = "event_handoff_1"
    scope_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    extraction_status: ExtractionStatus
    semantic_completeness: SemanticCompleteness
    events: tuple[ProjectedEvent, ...] = Field(max_length=MAX_EVENTS)
    relations: tuple[ProjectedRelation, ...] = Field(max_length=MAX_RELATIONS)
    signals: tuple[ProgramSignal, ...] = Field(max_length=MAX_SIGNALS)
    inspected_evidence_ids: tuple[EvidenceID, ...] = Field(min_length=1, max_length=MAX_EVENT_REFS)
    program_facts_source: Literal["parser_rules"] = "parser_rules"
    rules_complete: bool
    parser_warning_count: int = Field(ge=0, le=100000)
    review_required: bool
    authentication_verification: Literal["not_verified"] = "not_verified"
    coverage: InputCoverage

    @model_validator(mode="after")
    def bind_scope(self):
        events = {event.id for event in self.events}
        for prefix, collection in (("v", self.events), ("r", self.relations), ("s", self.signals)):
            for index, item in enumerate(collection, 1):
                if item.id != f"{prefix}_{self.scope_id}_{index:03d}":
                    raise ValueError("INVALID_EVENT_REFERENCE")
                if any(not ref.startswith(f"e_{self.scope_id}_") for ref in item.evidence_ids):
                    raise ValueError("INVALID_EVIDENCE_REFERENCE")
        if any(not ref.startswith(f"e_{self.scope_id}_") for ref in self.inspected_evidence_ids):
            raise ValueError("INVALID_EVIDENCE_REFERENCE")
        if any(
            relation.source_event not in events
            or relation.target_event not in events
            or relation.source_event == relation.target_event
            for relation in self.relations
        ):
            raise ValueError("INVALID_EVENT_REFERENCE")
        return self


class EventSupportBinding(EventContract):
    source_id: SourceID | None
    evidence_refs: list[EvidenceID] = Field(max_length=MAX_EVENT_REFS)


class EventReasonSlots(EventContract):
    ACCOUNT_ACCESS_REQUEST: EventSupportBinding | None
    SECRET_DISCLOSURE_REQUEST: EventSupportBinding | None
    EXECUTION_REQUEST: EventSupportBinding | None
    PAYMENT_REQUEST: EventSupportBinding | None
    COERCIVE_ACTION_REQUEST: EventSupportBinding | None
    LINKED_EXECUTION_REQUEST: EventSupportBinding | None
    ANALYSIS_MANIPULATION: EventSupportBinding | None
    URL_DECEPTION: EventSupportBinding | None
    PROGRAM_RULE_MATCH: EventSupportBinding | None
    NO_RISK_FACTS: EventSupportBinding | None
    EVIDENCE_INSUFFICIENT: EventSupportBinding | None
    SIMULATED_ANALYSIS: EventSupportBinding | None


class EventDecisionCore(EventContract):
    classification: Literal["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]
    reason_slots: EventReasonSlots
    uncertainty_codes: list[EventUncertainty] = Field(max_length=6)

    @property
    def evidence_refs(self) -> list[str]:
        return sorted(
            {
                ref
                for binding in self.reason_slots.__dict__.values()
                if binding
                for ref in binding.evidence_refs
            }
        )

    @property
    def reason_codes(self) -> list[str]:
        return [code for code, binding in self.reason_slots.__dict__.items() if binding is not None]

    @property
    def explanations(self) -> list:
        return []


class EventCoreResponse(EventContract):
    decision: EventDecisionCore


class EventSupportViolation(EventContract):
    reason_code: EventReason | None
    condition: Literal[
        "source_unknown",
        "qualification_missing",
        "evidence_missing",
        "evidence_not_linked",
        "evidence_duplicate",
        "unsupported_classification",
        "contradictory_selection",
    ]
    source_kind: Literal["event", "relation", "signal", "none", "unavailable"]
    available_evidence_count: int = Field(ge=0, le=4)
    matching_evidence_count: int = Field(ge=0, le=4)
    invalid_evidence_count: int = Field(ge=0, le=4)


class EventSupportError(ValueError):
    def __init__(self, violations: list[EventSupportViolation], code="UNSUPPORTED_REASON"):
        self.violations = violations
        super().__init__(code)
