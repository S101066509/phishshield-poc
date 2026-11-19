# 檔案功能：驗證檔案格式、內容與大小，將 EML 或 UTF-8 文字交給對應解析器。

import hashlib
import unicodedata
from pathlib import Path

from app.analysis.parser.eml_parser import _run_isolated
from app.analysis.parser.limits import ParseError, ParseLimits, require_limit
from app.domain.email_models import NormalizedEmail
from app.domain.enums import EmailSource

SUPPORTED_EXTENSIONS = {".eml": EmailSource.EML_UPLOAD, ".txt": EmailSource.PASTED_TEXT}
BINARY_SIGNATURES = (
    b"%PDF-",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # Outlook MSG / OLE
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"GIF87a",
    b"GIF89a",
    b"\x1f\x8b",
    b"\x7fELF",
)


def validate_file_content(raw: bytes, source: EmailSource) -> bytes:
    if raw.startswith(BINARY_SIGNATURES):
        raise ParseError("UNSUPPORTED_FILE_CONTENT")
    if source == EmailSource.PASTED_TEXT:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ParseError("INVALID_TEXT_ENCODING") from exc
        if any(unicodedata.category(c) == "Cc" and c not in "\t\r\n\f" for c in text):
            raise ParseError("UNSUPPORTED_FILE_CONTENT")
        return text.encode("utf-8")
    if raw.startswith(b"From "):
        raise ParseError("UNSUPPORTED_MAILBOX_FORMAT")
    return raw


def parse_file(
    path: str | Path,
    limits: ParseLimits | None = None,
    *,
    expected_extension: str | None = None,
) -> NormalizedEmail:
    """Accept a single .eml or UTF-8 .txt; extension matching is case-insensitive."""
    path = Path(path)
    extension = path.suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS or (
        expected_extension is not None and extension != expected_extension
    ):
        raise ParseError("UNSUPPORTED_FILE_TYPE")
    limits = limits or ParseLimits()
    try:
        if not path.is_file():
            raise ParseError("INPUT_READ_FAILED")
        with path.open("rb") as handle:
            raw = handle.read(limits.max_input_bytes + 1)
    except OSError as exc:
        raise ParseError("INPUT_READ_FAILED") from exc
    require_limit(len(raw), limits.max_input_bytes, "INPUT_TOO_LARGE")
    source = SUPPORTED_EXTENSIONS[extension]
    return parse_file_bytes(raw, source, limits)


def parse_file_bytes(raw: bytes, source: EmailSource, limits: ParseLimits) -> NormalizedEmail:
    require_limit(len(raw), limits.max_input_bytes, "INPUT_TOO_LARGE")
    checked = validate_file_content(raw, source)
    result = _run_isolated(checked, source, limits)
    # A UTF-8 BOM may be removed for display, but hash always identifies original bytes.
    result.content_hash = hashlib.sha256(raw).hexdigest()
    return result
