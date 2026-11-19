# 檔案功能：將貼上文字轉為統一郵件資料，保留原文並標示缺少的郵件資訊。

from app.analysis.parser.eml_parser import _run_isolated
from app.analysis.parser.limits import ParseError, ParseLimits, require_limit
from app.domain.email_models import NormalizedEmail
from app.domain.enums import EmailSource


def parse_pasted_text(text: str, limits: ParseLimits | None = None) -> NormalizedEmail:
    """Treat paste as literal text, even if it resembles MIME, HTML, or system instructions."""
    if not isinstance(text, str):
        raise ParseError("INVALID_INPUT_TYPE")
    limits = limits or ParseLimits()
    require_limit(len(text), limits.max_text_chars, "TEXT_LIMIT_EXCEEDED")
    try:
        raw = text.encode("utf-8")
    except UnicodeError as exc:
        raise ParseError("INVALID_TEXT_ENCODING") from exc
    return _run_isolated(raw, EmailSource.PASTED_TEXT, limits)
