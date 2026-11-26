# 檔案功能：定義寄件差異、可疑網址、社交工程與附件中繼資料的威脅訊號規則。

import re
from email.utils import getaddresses
from pathlib import PurePosixPath
from urllib.parse import parse_qsl, urlsplit

from app.analysis.parser.normalizer import (
    analysis_view,
    normalize_address,
    normalize_hostname,
    normalize_url,
)
from app.analysis.rules.base import SignalRule
from app.analysis.rules.text import pattern_refs
from app.domain.email_models import NormalizedEmail

CREDENTIAL_PATTERN = re.compile(
    r"\b(?:provide|enter|verify|confirm|submit|send)\s+(?:(?:your|the)\s+)?"
    r"(?:password|credentials|login\s+details|otp|verification\s+code)\b"
    r"|(?:輸入|输入|提供|傳送|发送|驗證|验证).{0,12}(?:密碼|密码|帳密|驗證碼|验证码)"
)
URGENCY_PATTERN = re.compile(
    r"\b(?:urgent|immediately|within\s+\d+\s+(?:hours?|minutes?)|"
    r"account\s+(?:will\s+be\s+)?suspended)\b"
    r"|立即|緊急|紧急|限時|限时|(?:帳號|账号).{0,6}停用"
)
# Static pattern list, not current reputation or proof of maliciousness.
SHORTENERS = frozenset({"bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly"})
REDIRECT_KEYS = frozenset(
    {
        "url",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "next",
        "continue",
        "return",
        "returnurl",
        "destination",
        "target",
    }
)
ATTACHMENT_SUFFIXES = frozenset(
    {
        ".exe",
        ".scr",
        ".com",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".hta",
        ".msi",
        ".lnk",
        ".iso",
        ".img",
        ".docm",
        ".xlsm",
        ".pptm",
        # 網頁偷渡與壓縮封存副檔名（僅檢視檔名中繼資料，不開啟或解析附件內容）。
        ".html",
        ".htm",
        ".shtml",
        ".svg",
        ".mhtml",
        ".zip",
        ".rar",
        ".7z",
    }
)


def sender_reply_mismatch(email: NormalizedEmail) -> list[str]:
    if not email.sender or not email.reply_to:
        return []
    # Only compare verifiable domain components; local-part differences are common.
    try:
        sender = normalize_hostname(email.sender.rsplit("@", 1)[1]).rstrip(".")
        reply = normalize_hostname(email.reply_to.rsplit("@", 1)[1]).rstrip(".")
    except (IndexError, UnicodeError, ValueError):
        return []
    if sender != reply and email.headers.get("from") and email.headers.get("reply-to"):
        refs = []
        for name, mailbox in (("from", email.sender), ("reply-to", email.reply_to)):
            for index, value in enumerate(email.headers[name]):
                if any(normalize_address(addr) == mailbox for _, addr in getaddresses([value])):
                    refs.append(f"header:{name}:{index}")
                    break
        return refs if len(refs) == 2 else []
    return []


def usable_urls(email: NormalizedEmail):
    for index, url in enumerate(email.urls):
        # A guessed boundary never becomes a deterministic comparison target.
        if not url.boundary_ambiguous and not url.parse_warning and url.normalized_url:
            yield index, url


def display_mismatch(email: NormalizedEmail) -> list[str]:
    references = []
    for index, url in usable_urls(email):
        display = url.display_text.strip()
        if not display:
            continue
        if re.fullmatch(r"[\w.-]+\.[\w-]+", display):
            display = "https://" + display
        displayed = normalize_url(display, "", "display")
        if (
            not displayed.parse_warning
            and displayed.hostname
            and url.hostname
            and displayed.hostname.rstrip(".") != url.hostname.rstrip(".")
        ):
            references.append(f"url:{index}")
    return references


def short_urls(email: NormalizedEmail) -> list[str]:
    return [
        f"url:{index}"
        for index, url in usable_urls(email)
        if (url.hostname or "").rstrip(".") in SHORTENERS
    ]


def redirect_urls(email: NormalizedEmail) -> list[str]:
    references = []
    for index, url in usable_urls(email):
        fields = parse_qsl(urlsplit(url.normalized_url).query, max_num_fields=1000)
        for key, value in fields:
            if key.casefold() in REDIRECT_KEYS and value.lower().startswith(
                ("http://", "https://")
            ):
                target = normalize_url(value, "", "redirect")
                if not target.parse_warning:
                    references.append(f"url:{index}")
                    break
    return references


def attachment_metadata(email: NormalizedEmail) -> list[str]:
    references = []
    for index, attachment in enumerate(email.attachments_metadata):
        name = analysis_view(attachment.filename or "").text.rstrip(" .").replace("\\", "/")
        if PurePosixPath(name).suffix in ATTACHMENT_SUFFIXES:
            references.append(f"attachment:{index}")
    return references


def threat_rules() -> tuple[SignalRule, ...]:
    return (
        SignalRule(
            "EMAIL_REPLY_TO_DOMAIN_MISMATCH",
            "email_threat",
            "low",
            "寄件者與 Reply-To 網域不同；需人工確認寄件情境。",
            sender_reply_mismatch,
            version="1.0.0",
        ),
        SignalRule(
            "EMAIL_URL_DISPLAY_MISMATCH",
            "email_threat",
            "medium",
            "連結顯示網域與實際 href 網域不同。",
            display_mismatch,
        ),
        SignalRule(
            "EMAIL_SHORT_URL",
            "email_threat",
            "low",
            "網址符合本機短網址網域清單，未跟隨重導。",
            short_urls,
        ),
        SignalRule(
            "EMAIL_REDIRECT_PARAMETER",
            "email_threat",
            "low",
            "網址參數含另一個 HTTP(S) 目的地，未發出網路請求。",
            redirect_urls,
        ),
        SignalRule(
            "EMAIL_CREDENTIAL_REQUEST",
            "email_threat",
            "medium",
            "文字包含帳密或驗證碼提供要求；這是文字訊號。",
            lambda email: pattern_refs(email, CREDENTIAL_PATTERN),
            version="1.0.0",
        ),
        SignalRule(
            "EMAIL_URGENCY",
            "email_threat",
            "low",
            "文字包含緊迫或帳號停用語句；合法郵件也可能出現。",
            lambda email: pattern_refs(email, URGENCY_PATTERN),
            version="1.0.0",
        ),
        SignalRule(
            "EMAIL_ATTACHMENT_EXTENSION",
            "email_threat",
            "medium",
            "附件檔名符合可執行、巨集或容器副檔名清單，未分析內容。",
            attachment_metadata,
        ),
    )
