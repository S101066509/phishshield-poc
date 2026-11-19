# 檔案功能：整理規則可搜尋的文字來源，將分析視圖命中映射回原始證據。

import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from app.analysis.parser.normalizer import AnalysisView, analysis_view
from app.domain.email_models import NormalizedEmail

_SOURCES: ContextVar[tuple[int, list] | None] = ContextVar("rule_text_sources", default=None)


@dataclass
class TextEvidence:
    original: str
    view: AnalysisView
    reference: str | None
    segments: tuple[tuple[int, int, str], ...] = ()

    def refs(self, start: int, end: int) -> list[str]:
        first, last = self.view.original_span(start, end)
        return self.original_refs(first, last)

    def original_refs(self, first: int, last: int) -> list[str]:
        if not 0 <= first < last <= len(self.original):
            raise ValueError("INVALID_TEXT_EVIDENCE_SPAN")
        if self.segments:
            return [ref for left, right, ref in self.segments if left < last and right > first]
        if self.reference is not None:
            return [self.reference]
        return [f"body:span:{first}-{last}"]


def text_sources(email: NormalizedEmail) -> list[TextEvidence]:
    cached = _SOURCES.get()
    if cached is not None and cached[0] == id(email):
        return cached[1]
    sources = [TextEvidence(email.body_text, analysis_view(email.body_text), None)]
    sources.extend(
        TextEvidence(text, analysis_view(text), f"hidden:{i}")
        for i, text in enumerate(email.hidden_texts)
    )
    if len(email.hidden_texts) > 1:
        # Parser preserves text nodes separately. Join for screening only and retain
        # every contributing original reference, without asserting a shared HTML parent.
        joined = " ".join(email.hidden_texts)
        segments = []
        offset = 0
        for index, text in enumerate(email.hidden_texts):
            segments.append((offset, offset + len(text), f"hidden:{index}"))
            offset += len(text) + 1
        sources.append(TextEvidence(joined, analysis_view(joined), None, tuple(segments)))
    sources.extend(
        TextEvidence(value, analysis_view(value), f"header:{name}:{i}")
        for name, values in sorted(email.headers.items())
        for i, value in enumerate(values)
    )
    for index, url in enumerate(email.urls):
        for value in dict.fromkeys([url.href, url.display_text, url.raw_candidate or ""]):
            if value:
                sources.append(TextEvidence(value, analysis_view(value), f"url:{index}"))
    for index, attachment in enumerate(email.attachments_metadata):
        if attachment.filename:
            value = attachment.filename
            sources.append(TextEvidence(value, analysis_view(value), f"attachment:{index}"))
    return sources


@contextmanager
def text_context(email: NormalizedEmail):
    sources = text_sources(email)
    token = _SOURCES.set((id(email), sources))
    try:
        yield
    finally:
        _SOURCES.reset(token)


def pattern_refs(email: NormalizedEmail, pattern: re.Pattern) -> list[str]:
    references = []
    for source in text_sources(email):
        # Aggregate one bounded evidence match per source, never silently discard the email.
        match = pattern.search(source.view.text)
        if match:
            references.extend(source.refs(match.start(), match.end()))
    return references
