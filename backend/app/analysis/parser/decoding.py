# 檔案功能：依宣告編碼與 BOM 解碼郵件內容，保留編碼衝突及恢復警告。

import codecs


def decode_bytes(payload: bytes, charset: str | None, warnings: list[str]) -> str:
    """Use explicit encodings/BOMs; never guess ambiguous unlabelled legacy encodings."""
    declared = charset
    unknown = False
    has_bom = False
    try:
        codec = codecs.lookup(charset or "utf-8")
        if not codec._is_text_encoding:
            raise LookupError("Not a text codec")
        encoding = codec.name
    except LookupError:
        unknown = True
        warnings.append("UNKNOWN_CHARSET")
        encoding = "utf-8"
    for marker, bom_encoding, compatible in (
        (codecs.BOM_UTF32_LE, "utf-32", {"utf-32", "utf-32-le"}),
        (codecs.BOM_UTF32_BE, "utf-32", {"utf-32", "utf-32-be"}),
        (codecs.BOM_UTF8, "utf-8-sig", {"utf-8", "utf-8-sig"}),
        (codecs.BOM_UTF16_LE, "utf-16", {"utf-16", "utf-16-le"}),
        (codecs.BOM_UTF16_BE, "utf-16", {"utf-16", "utf-16-be"}),
    ):
        if payload.startswith(marker):
            has_bom = True
            if declared and encoding not in compatible:
                warnings.append("CHARSET_BOM_CONFLICT")
            encoding = bom_encoding
            break
    else:
        if not declared and not payload.isascii():
            warnings.append("MISSING_CHARSET")
    try:
        text = payload.decode(encoding)
        if declared and not has_bom and not unknown and not payload.isascii():
            try:
                utf8_text = payload.decode("utf-8")
            except UnicodeError:
                pass
            else:
                if utf8_text != text:
                    # Both readings are valid. Preserve the declared reading for human review.
                    warnings.append("CHARSET_AMBIGUOUS")
        if unknown:
            warnings.append("CHARSET_FALLBACK")
        return text
    except (LookupError, UnicodeError):
        warnings.append("CHARSET_FALLBACK")
    # Limited, explicit compatibility families, not statistical language guessing.
    family = {"big5": "cp950", "gb2312": "gb18030", "gbk": "gb18030"}.get(encoding)
    for alternative in ([family] if family else []) + ["utf-8"]:
        try:
            text = payload.decode(alternative)
            warnings.append("CHARSET_RECOVERED")
            return text
        except UnicodeError:
            continue
    warnings.append("DECODE_REPLACEMENT_PRESENT")
    return payload.decode("utf-8", errors="replace")
