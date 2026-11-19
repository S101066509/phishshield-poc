# 檔案功能：定義產品發布狀態與執行期契約版本，供分析資料驗證及相容性檢查。

# 正式釋出前，依使用者指示將專案自有版本固定為 1.0.0，不自行升版。
PRODUCT_VERSION = "1.0.0"

# 下列識別由分析管線與資料契約實際使用，不代表產品發布版號。
# 純工程施工修訂另存於 development/ 文件，不由應用程式載入。
# 同版提示須以 analysis_method、judgment_format 及結構共同識別，歷史資料不重新標號。
PARSER_VERSION = "1.0.0"
RULESET_VERSION = "1.0.0"
LLM_PIPELINE_VERSION = "1.0.0"
PROMPT_A_VERSION = "1.0.0"
PROMPT_B_VERSION = "1.0.0"
PROPOSAL_PROMPT_A_VERSION = "1.0.0"
PROPOSAL_PROMPT_B_VERSION = "1.0.0"
# 明確比較入口沿用舊提示；不得冒稱受控交接。
LEGACY_PROMPT_A_VERSION = "1.0.0"
LEGACY_PROMPT_B_VERSION = "1.0.0"
LLM_SCHEMA_VERSION = "1.0.0"
STAGE_FAILURE_CONTRACT_VERSION = "1.0.0"
DECISION_VERSION = "1.0.0"
API_VERSION = "1.0.0"
DATABASE_SCHEMA_VERSION = "1.0.0"
UI_VERSION = "1.0.0"
EVALUATION_VERSION = "1.0.0"
REPORT_VERSION = "1.0.0"


def prompt_versions_for(analysis_method: str, judgment_format=None) -> tuple[str, str]:
    """Return the exact prompt identities permitted for one live analysis method."""
    if analysis_method == "structured_event_dual":
        if judgment_format != "event_facts_core_1":
            raise ValueError("UNKNOWN_JUDGMENT_FORMAT")
        return PROMPT_A_VERSION, PROMPT_B_VERSION
    if analysis_method == "structured_dual":
        if judgment_format == "proposal_v1":
            return PROPOSAL_PROMPT_A_VERSION, PROPOSAL_PROMPT_B_VERSION
        return PROMPT_A_VERSION, PROMPT_B_VERSION
    if analysis_method == "legacy_dual":
        return LEGACY_PROMPT_A_VERSION, LEGACY_PROMPT_B_VERSION
    if analysis_method == "single":
        return "not_executed", LEGACY_PROMPT_B_VERSION
    raise ValueError("UNKNOWN_ANALYSIS_METHOD")
