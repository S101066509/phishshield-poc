# 檔案功能：包裝各解析入口，將可處理的解析失敗轉為 FAILED 與 UNKNOWN。

from collections.abc import Callable
from pathlib import Path

from app.analysis.parser.eml_parser import parse_eml
from app.analysis.parser.file_adapter import parse_file, parse_file_bytes
from app.analysis.parser.limits import ParseError, ParseLimits
from app.analysis.parser.paste_adapter import parse_pasted_text
from app.domain.email_models import NormalizedEmail
from app.domain.enums import EmailSource
from app.domain.stage_failure import StageFailure, stage_failure

ParserResult = NormalizedEmail | StageFailure


def _capture(
    operation: Callable[[], NormalizedEmail], io_code="PARSER_UNAVAILABLE"
) -> ParserResult:
    try:
        return operation()
    except ParseError as exc:
        return stage_failure(1, exc.code, resource=exc.resource)
    except OSError:
        return stage_failure(1, io_code)
    except RuntimeError:
        return stage_failure(1, "PARSER_UNAVAILABLE")


def parse_file_result(
    path: str | Path, limits: ParseLimits | None = None, *, expected_extension: str | None = None
) -> ParserResult:
    if not isinstance(path, (str, Path)):
        return stage_failure(1, "INVALID_INPUT_TYPE")
    return _capture(
        lambda: parse_file(path, limits, expected_extension=expected_extension),
        io_code="INPUT_READ_FAILED",
    )


def parse_eml_result(raw: bytes, limits: ParseLimits | None = None) -> ParserResult:
    return _capture(lambda: parse_eml(raw, limits))


def parse_pasted_text_result(text: str, limits: ParseLimits | None = None) -> ParserResult:
    return _capture(lambda: parse_pasted_text(text, limits))


def parse_file_bytes_result(
    raw: bytes, source: EmailSource, limits: ParseLimits | None = None
) -> ParserResult:
    if not isinstance(raw, bytes) or source not in (
        EmailSource.EML_UPLOAD,
        EmailSource.PASTED_TEXT,
    ):
        return stage_failure(1, "INVALID_INPUT_TYPE")
    return _capture(lambda: parse_file_bytes(raw, source, limits or ParseLimits()))
