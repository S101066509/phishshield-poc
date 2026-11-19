# 檔案功能：偵測郵件中的提示注入、角色操控與隱藏或混淆指令訊號。

import base64
import binascii
import re
from urllib.parse import unquote

from app.analysis.parser.normalizer import analysis_view
from app.analysis.rules.base import SignalRule
from app.analysis.rules.text import TextEvidence, pattern_refs, text_sources
from app.domain.email_models import NormalizedEmail

PATTERNS = {
    "IGNORE_INSTRUCTIONS": re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)\b"
        r"|忽略.{0,8}(?:先前|之前|以上|所有).{0,8}(?:指令|規則|规则|提示)"
    ),
    "ROLE_OVERRIDE": re.compile(
        r"(?:\[|<|\b)(?:system|developer)(?:\]|>|:|\s+message\b)"
        r"|(?:我是|這是|这是|你現在是|你现在是).{0,12}(?:系統|系统|開發者|开发者).{0,8}(?:指令|提示|訊息|消息)"
    ),
    "FORCE_CLASSIFICATION": re.compile(
        r"(?<![a-z0-9_])(?:only\s+)?(?:output|return)\s*[:=]?\s*['\"]?safe(?![a-z0-9_])"
        r"|(?<![a-z0-9_])(?:classify|mark)(?![a-z0-9_]).{0,30}"
        r"(?<![a-z0-9_])as\s+safe(?![a-z0-9_])"
        r"|(?:只|僅|仅|必須|必须).{0,10}(?:輸出|输出|回傳|返回|標記|标记).{0,8}"
        r"(?<![a-z0-9_])safe(?![a-z0-9_])"
    ),
    "PROMPT_DISCLOSURE": re.compile(
        r"\b(?:reveal|show|print|leak|disclose)\b.{0,50}\b(?:system\s+prompt|api\s*key|secret|password)\b"
        r"|(?:洩漏|泄漏|顯示|显示|輸出|输出).{0,20}(?:系統提示|系统提示|api\s*key|金鑰|密鑰|密钥)"
    ),
    "TOOL_EXECUTION": re.compile(
        r"\b(?:execute|run)\s+(?:shell|python|bash|powershell|command)\b"
        r"|\b(?:call|invoke)\s+(?:an?\s+)?(?:api|tool)\b"
        r"|(?:執行|执行).{0,12}(?:命令|指令|程式|程序|shell|python)"
        r"|(?:呼叫|调用).{0,12}(?:api|工具)"
    ),
}
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,2048}={0,2}(?![A-Za-z0-9+/=])")
PERCENT_TOKEN = re.compile(r"[^\s<>\"']+")
PERCENT_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")


def has_instruction(text: str) -> bool:
    return any(pattern.search(text) for pattern in PATTERNS.values())


def hidden_instruction(email: NormalizedEmail) -> list[str]:
    references = []
    for source in text_sources(email):
        if not (source.segments or (source.reference or "").startswith("hidden:")):
            continue
        for pattern in PATTERNS.values():
            match = pattern.search(source.view.text)
            if match:
                references.extend(source.refs(match.start(), match.end()))
                break
    return references


def _unicode_obfuscated_refs(source: TextEvidence) -> list[str]:
    for pattern in PATTERNS.values():
        for match in pattern.finditer(source.view.text):
            start, end = source.view.original_span(match.start(), match.end())
            references = source.refs(match.start(), match.end())
            if source.original[start:end].casefold() != match[0] or len(references) > 1:
                return references
    return []


def obfuscated_instruction(email: NormalizedEmail) -> list[str]:
    references = []
    for source in text_sources(email):
        if source.segments or source.view.text != source.original.casefold():
            references.extend(_unicode_obfuscated_refs(source))
        # Decode one bounded layer for detection only; no decoded content is executed or trusted.
        for token in BASE64_TOKEN.finditer(source.original):
            try:
                decoded = base64.b64decode(token[0], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeError):
                continue
            if has_instruction(analysis_view(decoded).text):
                references.extend(source.original_refs(token.start(), token.end()))
                break
        # One bounded percent-decoding layer, used only as a signal, never as an action.
        for token in PERCENT_TOKEN.finditer(source.original):
            if len(token[0]) > 2048 or not PERCENT_ESCAPE.search(token[0]):
                continue
            try:
                decoded = unquote(token[0], encoding="utf-8", errors="strict")
            except UnicodeError:
                continue
            if has_instruction(analysis_view(decoded).text):
                references.extend(source.original_refs(token.start(), token.end()))
                break
    return references


def injection_rules() -> tuple[SignalRule, ...]:
    descriptions = {
        "IGNORE_INSTRUCTIONS": "文字要求忽略既有指令。",
        "ROLE_OVERRIDE": "文字自稱或嘗試覆寫系統／開發者角色。",
        "FORCE_CLASSIFICATION": "文字要求固定輸出 SAFE 分類。",
        "PROMPT_DISCLOSURE": "文字要求揭露提示或秘密。",
        "TOOL_EXECUTION": "文字要求呼叫工具或執行命令，未執行任何操作。",
    }
    rules = tuple(
        SignalRule(
            f"INJECTION_{name}",
            "prompt_injection",
            "medium",
            descriptions[name],
            lambda email, pattern=pattern: pattern_refs(email, pattern),
            version="1.0.0",
        )
        for name, pattern in PATTERNS.items()
    )
    return rules + (
        SignalRule(
            "INJECTION_HIDDEN_INSTRUCTION",
            "prompt_injection",
            "medium",
            "可能隱藏內容中出現分析操控指令。",
            hidden_instruction,
            version="1.0.0",
        ),
        SignalRule(
            "INJECTION_OBFUSCATED_INSTRUCTION",
            "prompt_injection",
            "medium",
            "Unicode、隱藏文字分段或單層 Base64／percent encoding 中出現操控指令，需核對原文。",
            obfuscated_instruction,
            version="1.0.0",
        ),
    )
