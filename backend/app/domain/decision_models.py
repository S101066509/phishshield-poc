# 檔案功能：定義最終決策、人工覆核及可信情報覆蓋的稽核資料契約。

from datetime import datetime
from typing import Literal

from pydantic import Field, computed_field, model_validator

from app.domain.analysis_models import FinalAnalysisResult
from app.domain.email_models import Contract, ReviewItem
from app.domain.versions import DECISION_VERSION


class OverrideAudit(Contract):
    rule_id: str
    rule_version: str
    source_id: str
    source_version: str
    evidence_ref: str
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime
    expires_at: datetime
    verified_at: datetime


class DecisionResult(FinalAnalysisResult):
    decision_version: str = DECISION_VERSION
    simulation: bool = False
    failed_phase: Literal[1, 2, 3, 4] | None = None
    review_items: list[ReviewItem] = Field(default_factory=list)
    override_audit: OverrideAudit | None = None

    @computed_field
    @property
    def analysis_completed(self) -> bool:
        return self.status == "COMPLETED"

    @computed_field
    @property
    def review_required(self) -> bool:
        return bool(self.review_items) or self.final_classification == "UNKNOWN"

    @model_validator(mode="after")
    def validate_decision(self):
        if self.override_applied != (self.override_audit is not None):
            raise ValueError("OVERRIDE_REQUIRES_VERIFIED_AUDIT")
        if self.override_audit and self.override_rule_id != self.override_audit.rule_id:
            raise ValueError("OVERRIDE_AUDIT_MISMATCH")
        if self.simulation and self.final_classification != "UNKNOWN":
            raise ValueError("SIMULATION_CANNOT_PRODUCE_A_REAL_VERDICT")
        if self.final_classification == "SAFE" and self.review_items:
            raise ValueError("SAFE_CANNOT_BYPASS_REVIEW")
        if self.status == "FAILED" and self.failed_phase is None:
            raise ValueError("FAILED_REQUIRES_PHASE")
        return self
