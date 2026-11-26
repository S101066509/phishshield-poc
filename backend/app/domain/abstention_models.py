# 檔案功能：定義程式從已驗證交接整理的棄權摘要，不代表模型內部理由或新的風險判斷。
from typing import Annotated, Literal

from pydantic import Field

from app.domain.email_models import Contract
from app.domain.handoff_models import Kind


class AbstentionSummary(Contract):
    contract: Literal["abstention_summary_1"] = "abstention_summary_1"
    source: Literal["validated_core_projection"] = "validated_core_projection"
    reason: Literal[
        "NO_REPORTED_RISK",
        "REPORTED_RISK_NOT_SELECTED",
        "SELECTED_RISK_WITHOUT_CONCLUSION",
    ]
    reported_kinds: list[Kind] = Field(max_length=8)
    uncertain_kinds: list[Kind] = Field(max_length=8)
    selected_kinds: list[Kind] = Field(max_length=8)
    unselected_kinds: list[Kind] = Field(max_length=8)
    model_internal_reason_available: Literal[False] = False
    summary: str = Field(min_length=1, max_length=900)
    next_steps: list[Annotated[str, Field(min_length=1, max_length=300)]] = Field(
        min_length=1, max_length=3
    )
