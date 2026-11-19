# 檔案功能：定義未完成分析的共同失敗格式，以受控原因表達 FAILED 與 UNKNOWN。

import re
from typing import Literal

from pydantic import ConfigDict

from app.domain.email_models import Contract
from app.domain.enums import AnalysisStatus, RiskClassification
from app.domain.reliability_models import ResourceDiagnostic
from app.domain.versions import PARSER_VERSION, RULESET_VERSION

REASONS = {
    "LLM_SCHEMA_UNSUPPORTED": "模型請求的結構不符合已核可的生成規格；未改用寬鬆格式。",
    "CORE_EVIDENCE_UNAVAILABLE": "必要的原文證據無法還原，核心判斷未採用。",
    "LLM_TEST_MODE_DISABLED": "離線模擬僅限測試工具，網站需配置可用模型端點。",
    "LLM_ENDPOINTS_OFFLINE": "此分析階段的模型端點均無法使用，服務離線，未完成分析。",
    "EMPTY_INPUT": "沒有可供分析的郵件內容。",
    "INVALID_INPUT_TYPE": "輸入資料型別不符。",
    "INVALID_TEXT_ENCODING": "文字編碼無法按指定方式解碼。",
    "UNSUPPORTED_FILE_TYPE": "檔案格式不支援或與指定輸入模式不符。",
    "UNSUPPORTED_FILE_CONTENT": "檔案內容不符合支援的郵件或文字格式。",
    "UNSUPPORTED_MAILBOX_FORMAT": "輸入為郵件集合，需先拆成單封郵件。",
    "INPUT_READ_FAILED": "無法讀取輸入檔案或資料。",
    "INPUT_TOO_LARGE": "輸入大小超過分析上限。",
    "MIME_PART_LIMIT_EXCEEDED": "MIME 部件數超過分析上限。",
    "MIME_DEPTH_LIMIT_EXCEEDED": "MIME 巢狀深度超過分析上限。",
    "HEADER_LIMIT_EXCEEDED": "郵件標頭長度超過分析上限。",
    "TEXT_LIMIT_EXCEEDED": "郵件文字長度超過分析上限。",
    "URL_LIMIT_EXCEEDED": "網址數量超過分析上限。",
    "URL_EVIDENCE_LIMIT_EXCEEDED": "網址證據總長度超過分析上限。",
    "ATTACHMENT_LIMIT_EXCEEDED": "附件數量超過分析上限。",
    "PARSE_TIMEOUT": "解析逾時，未完成分析。",
    "PARSE_FAILED": "郵件解析失敗，未完成分析。",
    "PARSER_UNAVAILABLE": "解析程序無法啟動或通訊失敗。",
    "UNKNOWN_RULE_ID": "規則設定包含未註冊的規則。",
    "DUPLICATE_RULE_ID": "規則設定包含重複的規則識別碼。",
    "INVALID_RULE_INPUT": "規則輸入或既有證據引用無效。",
    "RULE_EVALUATION_FAILED": "規則執行或輸出證據驗證失敗。",
    "INVALID_LLM_INPUT": "模型輸入、前階段版本或證據引用無效。",
    "LLM_NOT_CONFIGURED": "尚未設定模型服務；本次未呼叫模型。",
    "LLM_CONFIGURATION_INVALID": "模型端點、模型名稱或連線設定無效。",
    "LLM_AUTH_FAILED": "模型服務拒絕認證或存取權限，請確認 API Key 與權限。",
    "LLM_INPUT_TOO_LARGE": "模型輸入超過上限，未截斷或默認安全。",
    "LLM_TIMEOUT": "模型分析逾時，未完成分析。",
    "LLM_PROVIDER_FAILED": "模型服務呼叫失敗，未完成分析。",
    "LLM_CONNECTION_LOST": "模型連線中斷，有限重連後仍未完成分析。",
    "LLM_RECONNECT_FAILED": "模型失效連線無法清理或重建，已中止分析。",
    "LLM_RETRY_DELAY_LIMIT": "服務要求的等待時間超過重試上限，已中止分析。",
    "LLM_OUTPUT_INVALID": "模型輸出不符合結構或必要欄位要求。",
    "LLM_EVIDENCE_INVALID": "模型輸出的證據不存在或未提供給該模型。",
}


class StageFailure(Contract):
    """Incomplete analysis, never evidence that the mail itself is unsafe."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Literal[1, 2, 3]
    status: Literal[AnalysisStatus.FAILED] = AnalysisStatus.FAILED
    analysis_completed: Literal[False] = False
    final_classification: Literal[RiskClassification.UNKNOWN] = RiskClassification.UNKNOWN
    message: Literal["未成功完成分析"] = "未成功完成分析"
    classification_note: Literal["無法判斷郵件安全性，不代表安全或不安全"] = (
        "無法判斷郵件安全性，不代表安全或不安全"
    )
    error_code: str
    reason: str
    parser_version: str = PARSER_VERSION
    ruleset_version: str | None = None
    rule_id: str | None = None
    resource_diagnostic: ResourceDiagnostic | None = None
    review_required: Literal[True] = True


def stage_failure(
    phase: Literal[1, 2, 3], code: str, *, rule_id: str | None = None, resource=None
) -> StageFailure:
    # Never copy exception messages, input paths, mail or arbitrary provider text.
    if code not in REASONS:
        code = {1: "PARSE_FAILED", 2: "RULE_EVALUATION_FAILED", 3: "LLM_PROVIDER_FAILED"}[phase]
    if rule_id is not None and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", rule_id):
        rule_id = None
    return StageFailure(
        phase=phase,
        error_code=code,
        reason=REASONS[code],
        rule_id=rule_id,
        resource_diagnostic=resource,
        ruleset_version=RULESET_VERSION if phase in (2, 3) else None,
    )
