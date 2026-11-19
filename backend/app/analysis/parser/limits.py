# 檔案功能：集中定義解析資源與時間上限、受控錯誤及超限檢查。

from dataclasses import dataclass

from pydantic import Field

from app.domain.email_models import Contract
from app.domain.reliability_models import ResourceDiagnostic


class ParseLimits(Contract):
    max_input_bytes: int = Field(default=2_000_000, ge=1, le=20_000_000)
    max_mime_parts: int = Field(default=100, ge=1, le=1000)
    max_mime_depth: int = Field(default=10, ge=1, le=50)
    max_text_chars: int = Field(default=200_000, ge=1)
    max_urls: int = Field(default=200, ge=1)
    max_url_entities: int = Field(default=200, ge=1)
    max_url_scan_occurrences: int = Field(default=200, ge=1)
    max_html_anchor_occurrences: int = Field(default=200, ge=1)
    max_url_evidence_chars: int = Field(default=400_000, ge=1)
    max_attachments: int = Field(default=20, ge=0)
    max_header_chars: int = Field(default=32_000, ge=1)
    timeout_seconds: float = Field(default=5.0, gt=0, le=60, allow_inf_nan=False)


@dataclass
class ParseError(Exception):
    code: str
    resource: ResourceDiagnostic | None = None

    def __str__(self):
        return self.code


def require_limit(value: int, maximum: int, code: str, *, metric=None) -> None:
    if value > maximum:
        metrics = {
            "INPUT_TOO_LARGE": "raw_bytes",
            "HEADER_LIMIT_EXCEEDED": "header_chars",
            "TEXT_LIMIT_EXCEEDED": "text_chars",
            "MIME_PART_LIMIT_EXCEEDED": "mime_parts",
            "MIME_DEPTH_LIMIT_EXCEEDED": "mime_depth",
            "URL_LIMIT_EXCEEDED": "url_entities",
            "URL_EVIDENCE_LIMIT_EXCEEDED": "url_evidence_chars",
            "ATTACHMENT_LIMIT_EXCEEDED": "attachments",
        }
        raise ParseError(
            code,
            ResourceDiagnostic(
                metric=metric or metrics.get(code, "unavailable"), observed=value, limit=maximum
            ),
        )
