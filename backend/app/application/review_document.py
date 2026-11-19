# 檔案功能：保存人工覆核所需的原始文字、解碼正文及證據對照，不執行信件內容。

import hashlib
import re

from app.analysis.parser.result import parse_file_bytes_result
from app.domain.email_models import NormalizedEmail
from app.domain.enums import EmailSource
from app.domain.evidence import EvidenceRegistry


def review_document(
    raw: bytes, source: str, email, payload: dict, *, parse_display: bool = True
) -> dict:
    document = {
        "source": source,
        "content_hash": hashlib.sha256(raw).hexdigest(),
        "raw_text": raw.decode("utf-8", errors="replace"),
        "raw_text_note": (
            "原始檔以 UTF-8 顯示；無法解碼的位元組以替代字元呈現。MIME 編碼正文請對照解碼正文。"
        ),
        "parsed": None,
        "evidence": [],
    }
    if isinstance(email, NormalizedEmail):
        document["parsed"] = {
            "sender": email.sender,
            "reply_to": email.reply_to,
            "recipients": email.recipients,
            "subject": email.subject,
            "body_text": email.body_text,
        }
        display_text = email.body_text
        if (
            parse_display
            and source == "pasted_text"
            and re.search(r"<(?:html|body)\b", display_text, re.I)
        ):
            # Reuse the resource-limited parser process; never parse untrusted HTML
            # in the caller; async routes run this whole builder via run_parser_job.
            # The canonical analysis text and evidence offsets remain untouched.
            preview = parse_file_bytes_result(
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Transfer-Encoding: 8bit\r\n\r\n" + display_text.encode("utf-8"),
                EmailSource.EML_UPLOAD,
            )
            if isinstance(preview, NormalizedEmail):
                display_text = preview.body_text
        document["display_body_text"] = display_text
        registry = EvidenceRegistry(email)
        for item in payload.get("evidence", []):
            try:
                text = registry.resolve(item["ref"])
            except ValueError:
                text = None
            document["evidence"].append({"ref": item["ref"], "text": text})
    return document
