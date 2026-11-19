# 檔案功能：彙整郵件解析套件的公開函式，提供各輸入與受控結果介面。

from app.analysis.parser.eml_parser import parse_eml
from app.analysis.parser.file_adapter import parse_file
from app.analysis.parser.paste_adapter import parse_pasted_text
from app.analysis.parser.result import (
    parse_eml_result,
    parse_file_bytes_result,
    parse_file_result,
    parse_pasted_text_result,
)

__all__ = [
    "parse_eml",
    "parse_file",
    "parse_pasted_text",
    "parse_eml_result",
    "parse_file_result",
    "parse_file_bytes_result",
    "parse_pasted_text_result",
]
