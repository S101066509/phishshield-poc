# 檔案功能：以來源目錄與角色引用無損表示 A 材料；短郵件內聯直讀，長郵件啟用字串池壓縮。
import json
from collections import Counter

from app.analysis.llm.evidence_catalog import evidence_catalog
from app.domain.reliability_models import InputCoverage

# 短郵件低於此位元組門檻時維持直接內聯值，減少 4B 小模型在 source_values/catalog_ref 間跳轉負擔。
COMPACT_INDIRECTION_THRESHOLD_BYTES = 100_000


def coverage_for_mail(mail):
    count = len(evidence_catalog(mail))
    return InputCoverage(
        status="complete",
        source_units=count,
        represented_units=count,
        omitted_units=0,
        method="lossless_catalog",
    )


def compact_input(mail, rules, *, indirection_threshold_bytes=COMPACT_INDIRECTION_THRESHOLD_BYTES):
    original = evidence_catalog(mail)
    # URL/attachment registry strings are structured JSON. Body/headers remain exact strings.
    catalog = {
        ref: json.loads(value) if ref.startswith(("url:", "attachment:")) else value
        for ref, value in original.items()
    }
    base_roles = {
        "body_refs": [ref for ref in original if ref.startswith("body:")],
        "headers": {
            name: [f"header:{name}:{i}" for i in range(len(values))]
            for name, values in mail.headers.items()
        },
        "urls": [ref for ref in original if ref.startswith("url:")],
        "attachments_metadata": [ref for ref in original if ref.startswith("attachment:")],
        "hidden_refs": [ref for ref in original if ref.startswith("hidden:")],
        "auth_results": mail.auth_results.model_dump(mode="json"),
        "parse_warnings": mail.parse_warnings,
    }
    rules_payload = {
        "findings": [
            item.model_dump(
                mode="json", include={"rule_id", "category", "severity", "evidence_refs"}
            )
            for item in rules.findings
        ],
        "reviews": [
            item.model_dump(mode="json", include={"code", "evidence_refs"})
            for item in rules.review_items
        ],
    }
    coverage_payload = coverage_for_mail(mail).model_dump(mode="json")

    inline_payload = {
        "input_contract": "compact_mail_1",
        "email": {
            **base_roles,
            "sender_normalized": mail.sender,
            "reply_to_normalized": mail.reply_to,
            "subject": mail.subject,
        },
        "rules": rules_payload,
        "evidence_catalog": catalog,
        "source_values": {},
        "coverage": coverage_payload,
    }
    inline_bytes = len(
        json.dumps(inline_payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    )
    if inline_bytes < indirection_threshold_bytes:
        if restore_catalog(inline_payload) != original:
            raise ValueError("COMPACT_CATALOG_MISMATCH")
        return inline_payload

    counts = Counter()

    def count(value):
        if isinstance(value, str) and len(value) >= 32:
            counts[value] += 1
        elif isinstance(value, dict):
            for item in value.values():
                count(item)
        elif isinstance(value, list):
            for item in value:
                count(item)

    count(catalog)
    pool = {
        f"s{index}": value
        for index, value in enumerate(sorted(text for text, number in counts.items() if number > 1))
    }
    reverse = {value: key for key, value in pool.items()}

    def intern(value):
        if isinstance(value, str):
            return {"source_value": reverse[value]} if value in reverse else value
        if isinstance(value, dict):
            return {key: intern(item) for key, item in value.items()}
        if isinstance(value, list):
            return [intern(item) for item in value]
        return value

    def derived(value):
        if value is None:
            return None
        reference = next((ref for ref, text in original.items() if text == value), None)
        return {"evidence_ref": reference} if reference else value

    roles = {
        **base_roles,
        "sender_normalized": derived(mail.sender),
        "reply_to_normalized": derived(mail.reply_to),
        "subject": derived(mail.subject),
    }
    packed = intern(catalog)
    canonical = {}
    for ref, text in original.items():
        key = (ref.startswith(("url:", "attachment:")), text)
        if key in canonical:
            packed[ref] = {"catalog_ref": canonical[key]}
        else:
            canonical[key] = ref
    payload = {
        "input_contract": "compact_mail_1",
        "email": roles,
        "rules": rules_payload,
        "evidence_catalog": packed,
        "source_values": pool,
        "coverage": coverage_payload,
    }
    if restore_catalog(payload) != original:
        raise ValueError("COMPACT_CATALOG_MISMATCH")
    return payload


def restore_catalog(payload):
    def restore(value):
        if isinstance(value, dict):
            if set(value) == {"source_value"}:
                return payload["source_values"][value["source_value"]]
            return {key: restore(item) for key, item in value.items()}
        if isinstance(value, list):
            return [restore(item) for item in value]
        return value

    def entry(ref, visited=()):
        if ref in visited or len(visited) > 4:
            raise ValueError("COMPACT_CATALOG_MISMATCH")
        value = payload["evidence_catalog"][ref]
        if isinstance(value, dict) and set(value) == {"catalog_ref"}:
            return entry(value["catalog_ref"], (*visited, ref))
        return restore(value)

    values = {ref: entry(ref) for ref in payload["evidence_catalog"]}
    return {
        ref: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if ref.startswith(("url:", "attachment:"))
        else value
        for ref, value in values.items()
    }
