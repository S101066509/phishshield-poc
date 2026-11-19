# 檔案功能：根據解析警告與內容歧義建立人工覆核項目及證據引用。

from app.domain.email_models import NormalizedEmail, ReviewItem

MESSAGES = {
    "URL_BOUNDARY_AMBIGUOUS": "網址邊界有歧義，請比對完整候選、建議網址與原文位置。",
    "URL_PARSE_WARNING": "至少一筆網址無法可靠正規化，請查看該網址的 parse_warning。",
    "INTERNATIONALIZED_DOMAIN": "網址含國際化網域，請人工核對字形；此訊號不代表惡意。",
    "CHARSET_AMBIGUOUS": "宣告編碼與 UTF-8 都能解碼且結果不同，保留宣告結果，需人工確認。",
    "CHARSET_FALLBACK": "宣告編碼解碼失敗或未知，已使用備援，需核對原始郵件。",
    "CHARSET_RECOVERED": "已使用備援編碼恢復文字，請確認語意。",
    "CHARSET_BOM_CONFLICT": "BOM 與宣告編碼衝突，需確認正確文字。",
    "MISSING_CHARSET": "非 ASCII 內容缺少編碼標示，需人工確認。",
    "UNKNOWN_CHARSET": "未知或非文字編碼，需人工確認。",
    "DECODE_REPLACEMENT_PRESENT": "文字包含替代字元，可能已有資訊損失。",
    "MIXED_SCRIPT_TOKEN": "詞內混用拉丁、希臘或西里爾字母，請確認原始字形。",
    "UNICODE_FORMAT_CONTROLS": "含不可見格式字元，請核對原始及分析文字。",
    "UNICODE_BIDI_CONTROLS": "含雙向文字控制字元，顯示順序可能影響判讀。",
    "UNICODE_COMPATIBILITY_VARIANTS": "含相容字形，請核對原文與正規化比對文字。",
    "HIDDEN_CONTENT_PRESENT": "含可能隱藏的文字，仍須與正文一起分析。",
    "HTML_VISIBILITY_APPROXIMATE": "HTML 可見性僅作靜態提示，請同時檢查正文與隱藏文字。",
    "MALFORMED_MIME": "郵件 MIME 異常，解析可能不完整。",
    "MALFORMED_HEADER": "郵件標頭異常，需核對原始資料。",
    "MULTIPLE_SENDERS": "存在多個寄件者，請確認實際寄件身分。",
    "UNSUPPORTED_INLINE_CONTENT": "含未分析的內嵌內容，不能視為已完整檢查。",
    "MISSING_SENDER": "輸入缺少寄件者，無法評估寄件身分。",
    "MISSING_SUBJECT": "輸入缺少主旨，請按可用證據判讀。",
    "EMPTY_BODY": "沒有可見正文，請確認原始郵件及其他證據。",
    "UNTRUSTED_AUTH_HEADERS": "郵件自帶驗證標頭未經可信來源驗證，不能直接採信。",
}


def build_review_items(email: NormalizedEmail) -> list[ReviewItem]:
    """Flag uncertainty for humans; this function does not classify or approve mail."""
    items = []
    for code in email.parse_warnings:
        refs = []
        if code == "URL_BOUNDARY_AMBIGUOUS":
            refs = [f"url:{i}" for i, url in enumerate(email.urls) if url.boundary_ambiguous]
        elif code == "URL_PARSE_WARNING":
            refs = [f"url:{i}" for i, url in enumerate(email.urls) if url.parse_warning]
        elif code == "INTERNATIONALIZED_DOMAIN":
            refs = [
                f"url:{i}"
                for i, url in enumerate(email.urls)
                if any(label.startswith("xn--") for label in (url.hostname or "").split("."))
            ]
        elif code == "HIDDEN_CONTENT_PRESENT":
            refs = [f"hidden:{i}" for i in range(len(email.hidden_texts))]
        items.append(
            ReviewItem(
                code=code,
                message=MESSAGES.get(code, "解析有不確定性，需人工覆核。"),
                evidence_refs=refs,
            )
        )
    return items
