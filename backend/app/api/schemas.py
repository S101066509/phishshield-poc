# 檔案功能：定義提交郵件與分析模式的 API 請求格式，拒絕額外與不合法欄位。

from typing import Literal
from uuid import UUID

from pydantic import Field

from app.domain.email_models import Contract
from app.domain.llm_models import ProviderLabel


class ModelStatusResponse(Contract):
    connected: bool
    configuration_valid: bool
    availability: Literal["available", "missing", "unconfirmed", "offline"]
    service_reachable: bool
    provider: ProviderLabel | None
    model_a: str | None
    model_b: str | None
    reason_code: str
    stages: dict = Field(default_factory=dict)
    check_kind: Literal["model_availability_not_inference"]


class AnalyzeRequest(Contract):
    text: str = Field(
        min_length=1,
        max_length=1000000,
        description="郵件正文，1–1,000,000 字元。",
        examples=["您好，本週專案例會紀錄已整理完成，請參考內部文件。"],
    )
    mode: Literal["fake", "configured"] = Field(
        default="configured",
        description="configured 使用後端 A／B 端點池；fake 僅限明確開啟的測試環境。",
    )


class ReportExportRequest(Contract):
    analysis_ids: list[UUID] = Field(min_length=1, max_length=20)
    format: Literal["pdf", "zip"] = "pdf"
