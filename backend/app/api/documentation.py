# 檔案功能：組織 API 說明與回應欄位，註冊使用同站資源的 Swagger 互動文件入口。

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.domain.llm_models import OutputDiagnostic
from app.domain.reliability_models import (
    InputCoverage,
    ReliabilitySummary,
    RequestBudget,
    ResourceDiagnostic,
    UsageSnapshot,
)
from app.domain.versions import PRODUCT_VERSION

DOCS_ASSETS = Path(__file__).with_name("docs_assets")


def contract_schema(model):
    # Embedded OpenAPI schemas cannot resolve model-local #/$defs at the document root.
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    def inline(node):
        if isinstance(node, dict):
            if "$ref" in node:
                return inline(definitions[node["$ref"].removeprefix("#/$defs/")])
            return {key: inline(value) for key, value in node.items()}
        if isinstance(node, list):
            return [inline(value) for value in node]
        return node

    return inline(schema)


def diagnostic_schema():
    return contract_schema(OutputDiagnostic)


DESCRIPTION = f"""
PhishShield 郵件分析 API，產品版本為 {PRODUCT_VERSION}。

先用 **系統狀態** 確認服務與模型可用性，再用 **規則預覽** 檢視原文與初步訊號，
或直接用 **完整分析** 提交文字／單封 EML／UTF-8 TXT。**分析歷史** 提供分頁與原文證據。

- 預設 `mode=configured`，使用後端 A／B 各自的端點池，斷線或逾時後依序嘗試備援。
- `mode=fake` 僅限明確啟用模擬的測試環境；一般網站停用，不作備援。
- `mode=configured` 使用伺服器環境設定的 AI，完成後保存分析與原文。
- `status` 表示執行狀態，`final_classification` 表示分類。
  `UNKNOWN` 在前端顯示「交由人員判斷」，`FAILED` 表示分析未完成。
- 每次檔案請求接受一封 `.eml` 或 UTF-8 `.txt`，單檔上限 2,000,000 bytes。
  批次使用相同端點逐封提交。
- 在端點展開後按 **Try it out**，填寫參數，再按 **Execute**。
  完整分析 POST 會保存資料，請避免重複執行相同請求。

本機入口使用 `http://127.0.0.1:8000`，目前服務採同源與本機 Host 限制。
"""
TAGS = [
    {"name": "報告匯出", "description": "下載單筆 PDF、合併 PDF 或個別 PDF ZIP。"},
    {"name": "系統狀態", "description": "檢查服務、資料庫、版本與目前設定的 AI 模型。"},
    {"name": "規則預覽", "description": "解析郵件、提供原文與初步規則訊號，不寫入歷史。"},
    {"name": "完整分析", "description": "執行 Parser → Rule Engine → LLM A/B → Decision 並保存。"},
    {"name": "分析歷史", "description": "取得歷史摘要及單筆原文、證據與完整結果。"},
]
ERROR_SCHEMA = {
    "type": "object",
    "required": ["error_code", "status", "final_classification", "analysis_completed", "reason"],
    "properties": {
        "error_code": {"type": "string", "description": "請求邊界或服務錯誤代碼。"},
        "status": {"type": "string", "enum": ["FAILED"]},
        "final_classification": {"type": "string", "enum": ["UNKNOWN"]},
        "analysis_completed": {"type": "boolean", "const": False},
        "reason": {"type": "string", "description": "可供使用者閱讀的失敗說明。"},
    },
}
ANALYSIS_SCHEMA = {
    "type": "object",
    "required": [
        "analysis_id",
        "status",
        "final_classification",
        "analysis_completed",
        "simulation",
    ],
    "properties": {
        "analysis_id": {"type": "string", "format": "uuid"},
        "api_version": {
            "type": "string",
            "description": "產生此分析回覆及保存資料的 API 契約識別；舊紀錄可能缺少。",
        },
        "decision_version": {"type": "string"},
        "versions": {
            "type": "object",
            "description": "原始階段識別；llm_pipeline／llm_schema 缺失或未執行時為 null。",
            "properties": {
                "parser": {"type": "string"},
                "ruleset": {"type": "string"},
                "prompt_a": {"type": "string"},
                "prompt_b": {"type": "string"},
                "model_a": {"type": "string"},
                "model_b": {"type": "string"},
                "llm_pipeline": {"type": ["string", "null"]},
                "llm_schema": {"type": ["string", "null"]},
            },
        },
        "status": {"type": "string", "enum": ["COMPLETED", "FAILED"]},
        "analysis_completed": {"type": "boolean", "description": "整體分析是否完成。"},
        "final_classification": {
            "type": "string",
            "enum": ["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"],
        },
        "simulation": {"type": "boolean", "description": "true 代表離線模擬。"},
        "latency_ms": {
            "type": ["number", "null"],
            "description": "分析至覆核完成的實測毫秒數；不含保存／查回／網路，未知為 null。",
        },
        "latency_scope": {"type": ["string", "null"]},
        "created_at": {"type": ["string", "null"], "format": "date-time"},
        "started_at": {"type": ["string", "null"], "format": "date-time"},
        "completed_at": {
            "type": ["string", "null"],
            "format": "date-time",
            "description": "分析及覆核完成時間，不是資料庫 commit 時間；舊資料可能為 null。",
        },
        "persistence": {
            "type": "object",
            "description": "保存確認狀態；analysis_id 本身不代表已保存。舊紀錄可能缺少。",
            "properties": {
                "state": {"type": "string", "enum": ["saved", "not_saved", "unconfirmed"]},
                "reconciled": {
                    "type": "boolean",
                    "description": "是否在回覆異常後確認原交易已保存。",
                },
            },
        },
        "failed_phase": {"type": ["integer", "null"], "description": "失敗的 Phase 1–4。"},
        "analysis_reliability": contract_schema(ReliabilitySummary),
        "coverage": contract_schema(InputCoverage),
        "input_diagnostic": contract_schema(ResourceDiagnostic),
        "model_analysis": {
            "type": ["object", "null"],
            "description": "模型啟用、完成狀態、原因代碼及規則命中資訊，舊紀錄可能缺少。",
        },
        "model_diagnostics": {
            "type": "object",
            "description": (
                "模型未完成時的受限工程診斷；不含回覆原文，舊紀錄不補造，不呈現在讀者報告。"
            ),
            "properties": {
                "failed_stage": {"type": "string", "enum": ["input", "configuration", "a", "b"]},
                "diagnostic": {"anyOf": [diagnostic_schema(), {"type": "null"}]},
                "calls": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "stage": {"type": "string", "enum": ["a", "b"]},
                            "attempt": {"type": "integer"},
                            "error_code": {"type": ["string", "null"]},
                            "request_budget": {
                                "anyOf": [contract_schema(RequestBudget), {"type": "null"}]
                            },
                            "usage": {"anyOf": [contract_schema(UsageSnapshot), {"type": "null"}]},
                            "diagnostic": {
                                "anyOf": [diagnostic_schema(), {"type": "null"}],
                                "description": (
                                    "封閉 reason、constraint 與 Schema 頂層 fields；"
                                    "不含動態欄名或值。"
                                ),
                            },
                        },
                    },
                },
            },
        },
        "rule_findings": {"type": "array", "items": {"type": "object"}},
        "rule_signal_summary": {"type": "object", "description": "威脅／注入訊號數量。"},
        "analysis_explanation": {
            "type": "object",
            "description": (
                "模型摘要、理由與後端原文證據。reason_source 區分 "
                "deterministic_event_facts（程式依已驗證行為事實與來源產生）／"
                "deterministic_observations／structured_observations／legacy_unknown；"
                "presentation 區分程式整理、舊模型說明與展示降級。"
            ),
        },
        "analysis_trace": {
            "type": ["object", "null"],
            "description": (
                "目前 structured_dual／core_slots_1 保存八類觀察交接及 B 核心。"
                "已保存的 structured_event_dual／event_facts_core_1 仍保留 A 的 "
                "event_extraction_1、event_handoff_1、引用反向對照及 B 核心。"
                "依 method 與 judgment_format 分流，"
                "供工程追溯，不呈現在讀者報告，也不替舊紀錄補造事件。"
            ),
        },
        "source_document": {
            "type": ["object", "null"],
            "description": "原始文字、解析正文、寄收件資訊與證據對照，舊紀錄可能為 null。",
        },
        "errors": {"type": "array", "items": {"type": "object"}},
        "reason_codes": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}
COMMON_RESPONSES = {
    400: {"description": "Content-Length 無效。"},
    403: {"description": "Origin 與 Host 不符。"},
    408: {"description": "請求本文接收超過 10 秒。"},
    413: {"description": "請求本文或郵件大小超限。"},
    503: {"description": "資料庫、模型或分析服務未完成。"},
}
for value in COMMON_RESPONSES.values():
    value["content"] = {"application/json": {"schema": ERROR_SCHEMA}}
VALIDATION_RESPONSE = {
    "description": "欄位、模式、UUID 或分頁參數無效，或已保存的解析失敗。",
    "content": {"application/json": {"schema": {"oneOf": [ERROR_SCHEMA, ANALYSIS_SCHEMA]}}},
}
UNSUPPORTED_RESPONSE = {
    "description": "不支援的 Content-Type 或副檔名。",
    "content": {"application/json": {"schema": ERROR_SCHEMA}},
}
ANALYSIS_RESPONSES = {
    201: {
        "description": "分析流程完成並已保存，請同時檢視 simulation 與 final_classification。",
        "content": {"application/json": {"schema": ANALYSIS_SCHEMA}},
    },
    413: {
        "description": "郵件內容或請求超限，取得 analysis_id 時表示已建立失敗分析紀錄。",
        "content": {"application/json": {"schema": {"oneOf": [ERROR_SCHEMA, ANALYSIS_SCHEMA]}}},
    },
    415: UNSUPPORTED_RESPONSE,
    422: VALIDATION_RESPONSE,
    503: {
        "description": "模型／決策未完成，或服務／資料庫不可用。請先檢查 analysis_id 與歷史。",
        "content": {"application/json": {"schema": {"oneOf": [ERROR_SCHEMA, ANALYSIS_SCHEMA]}}},
    },
}


def register_documentation(app: FastAPI) -> None:
    @app.get("/docs", include_in_schema=False)
    async def swagger():
        return FileResponse(DOCS_ASSETS / "index.html", media_type="text/html")

    @app.get("/swagger", include_in_schema=False)
    async def swagger_alias():
        return RedirectResponse("/docs")

    app.mount("/api-docs-assets", StaticFiles(directory=DOCS_ASSETS), name="api-docs-assets")
