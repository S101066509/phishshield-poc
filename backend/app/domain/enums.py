# 檔案功能：定義郵件來源、分析執行狀態與風險分類的共用列舉。

from enum import StrEnum


class RiskClassification(StrEnum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    UNKNOWN = "UNKNOWN"


class AnalysisStatus(StrEnum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EmailSource(StrEnum):
    EML_UPLOAD = "eml_upload"
    PASTED_TEXT = "pasted_text"
