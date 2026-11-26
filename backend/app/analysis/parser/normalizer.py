# 檔案功能：正規化文字、地址與網址，建立 Unicode 分析視圖並保留原文位置。

import re
import unicodedata
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit

import idna

from app.domain.email_models import URLFinding

URL_PATTERN = re.compile(r"https?://[^\s<>\"'，。；、！？（）【】《》「」『』]+", re.IGNORECASE)
RAW_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
PROSE_SEPARATORS = "，。；、！？（）【】《》「」『』"
# 只免除標準全形 ASCII 標點與全形空白；英數及其他相容字形仍需覆核。
COMMON_CJK_LAYOUT = frozenset(
    "\u3000！＂＃＄％＆＇（）＊＋，－．／：；＜＝＞？＠［＼］＾＿｀｛｜｝～"
)


@dataclass
class URLCandidate:
    href: str
    start: int
    end: int
    raw_candidate: str
    raw_end: int
    boundary_reasons: list[str]


def url_candidates(text: str):
    """Retain the full contiguous token alongside a heuristic preferred boundary."""
    for match in URL_PATTERN.finditer(text):
        raw_match = RAW_URL_PATTERN.match(text, match.start())
        raw = raw_match[0]
        candidate = match[0].rstrip(".,;!?")
        while candidate.endswith(")") and candidate.count(")") > candidate.count("("):
            candidate = candidate[:-1]
        reasons = []
        if len(raw) > len(match[0]):
            reasons.append("PROSE_SEPARATOR")
        if len(candidate) < len(match[0]):
            reasons.append("TRAILING_PUNCTUATION_OR_WRAPPER")
        if "," in candidate or ";" in candidate:
            reasons.append("INTERNAL_PUNCTUATION")
        if candidate:
            yield URLCandidate(
                candidate,
                match.start(),
                match.start() + len(candidate),
                raw,
                raw_match.end(),
                reasons,
            )


def url_matches(text: str):
    """Yield text URL candidates, trimming common prose wrappers, not URL internals."""
    for candidate in url_candidates(text):
        yield candidate.href, candidate.start, candidate.end


@dataclass
class AnalysisView:
    text: str
    # Each analysis code point maps back to a half-open span in the original string.
    source_spans: list[tuple[int, int]]

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if not 0 <= start < end <= len(self.text):
            raise ValueError("INVALID_ANALYSIS_SPAN")
        return self.source_spans[start][0], self.source_spans[end - 1][1]


def analysis_view(text: str) -> AnalysisView:
    """Compatibility/case matching view; never replaces original evidence."""
    # Remove controls before grouping, so e + zero-width + accent still composes as é.
    positions = [index for index, char in enumerate(text) if unicodedata.category(char) != "Cf"]
    filtered = "".join(text[index] for index in positions)
    chunks: list[str] = []
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(filtered):
        end = index + 1
        hangul = unicodedata.name(filtered[index], "").startswith("HANGUL")
        while end < len(filtered) and (
            unicodedata.combining(filtered[end])
            or (hangul and unicodedata.name(filtered[end], "").startswith("HANGUL"))
        ):
            end += 1
        chunk = unicodedata.normalize("NFKC", filtered[index:end]).casefold()
        chunks.append(chunk)
        spans.extend([(positions[index], positions[end - 1] + 1)] * len(chunk))
        index = end
    return AnalysisView("".join(chunks), spans)


def unicode_signals(text: str) -> set[str]:
    signals: set[str] = set()
    if any(unicodedata.category(c) == "Cf" for c in text):
        signals.add("UNICODE_FORMAT_CONTROLS")
    if any(
        unicodedata.bidirectional(c)
        in {"RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI"}
        for c in text
    ):
        signals.add("UNICODE_BIDI_CONTROLS")
    if any(
        not char.isascii()
        and char not in COMMON_CJK_LAYOUT
        and unicodedata.normalize("NFKC", char) != char
        for char in text
    ):
        signals.add("UNICODE_COMPATIBILITY_VARIANTS")
    if "\ufffd" in text:
        signals.add("DECODE_REPLACEMENT_PRESENT")
    # Only flag mixed Latin/Greek/Cyrillic inside a token, not ordinary CJK + English prose.
    for token in re.findall(r"[^\W\d_]+", text):
        scripts = set()
        for character in token:
            name = unicodedata.name(character, "")
            for script in ("LATIN", "GREEK", "CYRILLIC"):
                if name.startswith(script):
                    scripts.add(script)
        if len(scripts) > 1:
            signals.add("MIXED_SCRIPT_TOKEN")
    return signals


def normalize_hostname(host: str) -> str:
    try:
        return str(ip_address(host))
    except ValueError:
        return idna.encode(host, uts46=True, transitional=False).decode("ascii").lower()


def normalize_text(text: str) -> str:
    # Preserve Unicode and interior whitespace so evidence offsets are unambiguous.
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def normalize_address(address: str) -> str:
    local, separator, domain = address.rpartition("@")
    if not separator:
        return address
    try:
        return local + "@" + normalize_hostname(domain)
    except (UnicodeError, ValueError):
        return address


def normalize_url(href: str, display_text: str, source_location: str) -> URLFinding:
    result = URLFinding(href=href, display_text=display_text, source_location=source_location)
    candidate = analysis_view(href).text
    # Preserve URL path/query case: only use the analysis view for detecting obfuscation.
    if candidate != href.casefold():
        result.analysis_url = candidate
    if any(unicodedata.category(c) in {"Cc", "Cf"} for c in href):
        result.parse_warning = "URL_CONTROL_CHARACTERS"
        return result
    if href != href.strip():
        result.parse_warning = "URL_SURROUNDING_WHITESPACE"
        return result
    try:
        parts = urlsplit(href)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            result.parse_warning = "UNSUPPORTED_OR_RELATIVE_URL"
            return result
        host = normalize_hostname(parts.hostname)
        port = parts.port  # Force malformed port validation.
        if parts.netloc.endswith(":"):
            result.parse_warning = "INVALID_URL"
            return result
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority += f":{port}"
        if parts.username is not None:
            # Retain userinfo as a potential threat signal, never dereference it.
            authority = parts.netloc.rsplit("@", 1)[0] + "@" + authority
        result.hostname = host
        # urlunsplit drops empty '?' / '#' delimiters; retain them as original URL evidence.
        normalized = f"{parts.scheme.lower()}://{authority}{parts.path}"
        if "?" in href.partition("#")[0]:
            normalized += "?" + parts.query
        if "#" in href:
            normalized += "#" + parts.fragment
        result.normalized_url = normalized
    except (ValueError, UnicodeError):
        result.parse_warning = "INVALID_URL"
    return result
