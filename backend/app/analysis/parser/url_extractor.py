# 檔案功能：收集正文與 HTML 網址，保留完整候選、建議邊界與來源證據。

from app.analysis.parser.limits import ParseLimits, require_limit
from app.analysis.parser.normalizer import (
    PROSE_SEPARATORS,
    analysis_view,
    normalize_url,
    url_candidates,
)
from app.domain.email_models import URLFinding


class URLCollector:
    """Bound all preferred URLs, complete candidates and display text together."""

    def __init__(self, limits: ParseLimits):
        self.limits = limits
        self.urls: list[URLFinding] = []
        self.evidence_chars = 0
        self.entities = set()

    def add(self, url: URLFinding) -> None:
        self.entities.add(url.normalized_url or url.href)
        require_limit(
            len(self.entities),
            self.limits.max_url_entities,
            "URL_LIMIT_EXCEEDED",
            metric="url_entities",
        )
        require_limit(
            len(self.urls) + 1,
            self.limits.max_url_scan_occurrences,
            "URL_LIMIT_EXCEEDED",
            metric="url_scan_occurrences",
        )
        require_limit(len(self.urls) + 1, self.limits.max_urls, "URL_LIMIT_EXCEEDED")
        size = len(url.href) + len(url.raw_candidate or "") + len(url.display_text)
        require_limit(
            self.evidence_chars + size,
            self.limits.max_url_evidence_chars,
            "URL_EVIDENCE_LIMIT_EXCEEDED",
        )
        self.evidence_chars += size
        self.urls.append(url)

    def add_html(self, href: str, display_text: str, location: str) -> None:
        # An explicit HTML href is authoritative about its own boundary, not trustworthiness.
        url = normalize_url(href, display_text, location)
        url.raw_candidate = href
        url.raw_source_location = location
        self.add(url)

    def add_text(self, text: str, location: str) -> None:
        seen = set()

        def reference(start: int, end: int) -> str:
            return f"body:span:{start}-{end}" if location == "body" else location

        def add(start: int, end: int, raw_end: int, reasons: list[str]) -> None:
            key = (start, end)
            if key in seen:
                return
            seen.add(key)
            url = normalize_url(text[start:end], text[start:end], reference(start, end))
            url.raw_candidate = text[start:raw_end]
            url.raw_source_location = reference(start, raw_end)
            url.boundary_reasons = sorted(set(reasons))
            self.add(url)

        for candidate in url_candidates(text):
            add(candidate.start, candidate.end, candidate.raw_end, candidate.boundary_reasons)
        view = analysis_view(text)
        for candidate in url_candidates(view.text):
            start, end = view.original_span(candidate.start, candidate.end)
            _, raw_end = view.original_span(candidate.start, candidate.raw_end)
            reasons = list(candidate.boundary_reasons)
            for offset in range(start, end):
                if text[offset] in PROSE_SEPARATORS:
                    end = offset
                    reasons.append("PROSE_SEPARATOR")
                    break
            if end > start:
                add(start, end, raw_end, reasons)
