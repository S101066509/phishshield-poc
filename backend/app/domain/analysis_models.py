# 檔案功能：定義規則發現、模型特徵與建議，以及最終分析結果的狀態契約。

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from app.domain.email_models import Contract
from app.domain.enums import AnalysisStatus, RiskClassification


class AnalysisError(Contract):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


class RuleFinding(Contract):
    rule_id: str
    rule_version: str
    category: Literal["email_threat", "prompt_injection"]
    severity: Literal["low", "medium", "high", "critical"]
    evidence_refs: list[str]
    summary: str
    evidence_source: str
    # A signal only; the decision layer must independently validate provenance.
    is_confirmed_malicious: bool = False


class Feature(Contract):
    feature_type: str
    description: str
    evidence_refs: list[str]


class FeatureResult(Contract):
    features: list[Feature]
    suspicious_url_refs: list[str]
    social_engineering_indicators: list[str]
    uncertainties: list[str]


class RiskJudgment(Contract):
    classification: RiskClassification
    reason_codes: list[str]
    evidence_refs: list[str]
    uncertainties: list[str]
    confidence: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)


class AnalysisVersions(Contract):
    parser: str
    ruleset: str
    prompt_a: str
    prompt_b: str
    model_a: str
    model_b: str
    # Legacy records and stages that did not enter the model pipeline remain unknown.
    llm_pipeline: str | None = None
    llm_schema: str | None = None


class FinalAnalysisResult(Contract):
    analysis_id: UUID
    status: AnalysisStatus
    final_classification: RiskClassification | None
    llm_classification: RiskClassification | None = None
    reason_codes: list[str] = Field(default_factory=list)
    rule_findings: list[RuleFinding] = Field(default_factory=list)
    override_applied: bool = False
    override_rule_id: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    errors: list[AnalysisError] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    versions: AnalysisVersions
    latency_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    latency_scope: Literal["analysis_through_review_excludes_persistence"] | None = None
    created_at: AwareDatetime | None = None
    started_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    token_usage: int | None = Field(default=None, ge=0)
    estimated_cost: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_state(self):
        if self.status in (AnalysisStatus.PENDING, AnalysisStatus.PROCESSING):
            if self.final_classification is not None:
                raise ValueError("Unfinished analyses must have null classification")
        elif self.status == AnalysisStatus.FAILED:
            if self.final_classification != RiskClassification.UNKNOWN or not self.errors:
                raise ValueError("Failed analyses require UNKNOWN and an error code")
        elif self.final_classification is None:
            raise ValueError("Completed analyses require a classification")
        if self.errors and self.final_classification == RiskClassification.SAFE:
            raise ValueError("Errors cannot produce SAFE")
        if self.override_applied:
            if (
                self.status != AnalysisStatus.COMPLETED
                or self.final_classification != RiskClassification.PHISHING
                or not self.override_rule_id
            ):
                raise ValueError("Override requires completed PHISHING and rule ID")
        elif self.override_rule_id is not None:
            raise ValueError("Override rule ID requires override_applied")
        return self
