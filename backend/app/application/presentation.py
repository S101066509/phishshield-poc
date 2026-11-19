# 檔案功能：將內部結果轉為不含郵件原文與模型自由文字的公開資料，保留可判讀的代碼與定位。

from typing import get_args
from urllib.parse import urlsplit

from app.analysis.rules import RuleEngine
from app.domain.decision_models import DecisionResult
from app.domain.email_models import NormalizedEmail
from app.domain.event_models import EventReason
from app.domain.handoff_models import Reason

CONTROLLED_CODES = {
    "MODEL_RECOMMENDATION",
    "SIMULATED_ANALYSIS",
    "EVIDENCE_INSUFFICIENT",
    "REVIEW_REQUIRED",
    "TRUSTED_MALICIOUS_URL",
    "UNKNOWN",
    "LLM_UNCERTAINTY",
    "UNVERIFIED_INTELLIGENCE",
    "EVENT_SEMANTIC_INCOMPLETE",
}


def present(result: DecisionResult) -> dict:
    from app.domain.stage_failure import REASONS

    controlled = (
        CONTROLLED_CODES
        | set(get_args(Reason))
        | set(get_args(EventReason))
        | set(REASONS)
        | {
            "INVALID_DECISION_INPUT",
            "INVALID_DECISION_CLOCK",
            "INTELLIGENCE_UNAVAILABLE",
            "REQUIRED_STAGE_FAILED",
            "ANALYSIS_TIMEOUT",
            "ANALYSIS_SERVICE_FAILED",
        }
    )
    known = {rule.id: rule for rule in RuleEngine().rules}
    output = result.model_dump(mode="json")
    output["reason_codes"] = list(
        dict.fromkeys(
            code if code in controlled else "MODEL_REASON_REDACTED" for code in result.reason_codes
        )
    )
    output["parse_warnings"] = ["PARSER_WARNING" for _ in result.parse_warnings]
    output["review_items"] = [
        dict(
            code=item.code if item.code in known or item.code in controlled else "REVIEW_REQUIRED",
            message="此項需人工判讀；原文未保存。",
            evidence_refs=item.evidence_refs,
        )
        for item in result.review_items
    ]
    output["rule_findings"] = [
        finding.model_dump(mode="json") | {"summary": known[finding.rule_id].summary}
        for finding in result.rule_findings
        if finding.rule_id in known
    ]
    refs = list(
        dict.fromkeys(
            [
                *result.evidence_refs,
                *[ref for item in result.rule_findings for ref in item.evidence_refs],
                *[ref for item in result.review_items for ref in item.evidence_refs],
            ]
        )
    )
    output["evidence"] = [
        dict(
            ref=ref,
            kind=ref.split(":")[0],
            retained_content=False,
            display="[CONTENT_NOT_RETAINED]",
        )
        for ref in refs
    ]
    output["privacy_note"] = (
        "不保存郵件原文、URL 值或模型自由文字；僅保存分類、受控代碼與證據定位。"
    )
    return output


def transient_urls(email):
    if not isinstance(email, NormalizedEmail):
        return []
    return [
        dict(
            ref=f"url:{index}",
            display=(
                f"{urlsplit(url.normalized_url).scheme}://{url.hostname}/[PATH_QUERY_REDACTED]"
                if url.hostname and url.normalized_url
                else "[URL_UNRESOLVED]"
            ),
            boundary_ambiguous=url.boundary_ambiguous,
        )
        for index, url in enumerate(email.urls)
    ]
