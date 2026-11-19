# 檔案功能：依統一郵件解析及驗證證據引用，拒絕不存在或越界的位置。

import re

from app.domain.email_models import NormalizedEmail


class EvidenceRegistry:
    """References resolve only against the exact normalized email instance."""

    def __init__(self, email: NormalizedEmail):
        self.email = email

    def resolve(self, reference: str) -> str:
        match = re.fullmatch(r"body:span:(0|[1-9]\d*)-(0|[1-9]\d*)", reference)
        if match:
            start, end = map(int, match.groups())
            if 0 <= start < end <= len(self.email.body_text):
                return self.email.body_text[start:end]
        match = re.fullmatch(r"(url|attachment|hidden):(0|[1-9]\d*)", reference)
        if match:
            kind, raw_index = match.groups()
            index = int(raw_index)
            items = {
                "url": self.email.urls,
                "attachment": self.email.attachments_metadata,
                "hidden": self.email.hidden_texts,
            }[kind]
            if index < len(items):
                item = items[index]
                return item if isinstance(item, str) else item.model_dump_json()
        match = re.fullmatch(r"header:([a-z0-9-]+):(0|[1-9]\d*)", reference)
        if match:
            name, raw_index = match.groups()
            values = self.email.headers.get(name, [])
            if int(raw_index) < len(values):
                return values[int(raw_index)]
        raise ValueError("INVALID_EVIDENCE_REFERENCE")

    def validate(self, references: list[str]) -> None:
        for reference in references:
            self.resolve(reference)
