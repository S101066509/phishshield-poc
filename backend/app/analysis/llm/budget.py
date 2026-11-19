# 檔案功能：計量完整請求各部分 bytes，以明示的字元估算及安全餘量檢查已設定的有效容量。
import json
from math import ceil

from app.domain.reliability_models import RequestBudget


def utf8_bytes(value):
    return len(value.encode("utf-8"))


def json_bytes(value):
    return utf8_bytes(json.dumps(value, ensure_ascii=False, allow_nan=False))


def request_budget(request, settings, payload):
    system_bytes = utf8_bytes(request.system_prompt)
    data_bytes = utf8_bytes(request.data_json)
    schema_bytes = utf8_bytes(request.response_schema_json)
    # JSON escaping + ordinary separators bound the installed SDK serialization. Padding
    # covers fixed SDK scalar fields, not HTTP headers/keys or unknown server prompt overhead.
    wire = json.dumps(
        {
            "model": request.model_id,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.data_json},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": json.loads(request.response_schema_json).get("title", "response"),
                    "strict": True,
                    "schema": json.loads(request.response_schema_json),
                },
            },
            "max_completion_tokens": request.max_output_tokens,
            "stream": False,
            "reasoning_effort": "medium",
            "temperature": settings.temperature,
            **({"seed": settings.seed} if settings.seed is not None else {}),
        },
        ensure_ascii=True,
        allow_nan=False,
    )
    total = utf8_bytes(wire) + 256
    combined = request.system_prompt + request.data_json + request.response_schema_json
    non_ascii = sum(ord(char) > 127 for char in combined)
    # This is a deliberately conservative character heuristic, not bytes==tokens and
    # not a tokenizer. Server framing/unknown vocabulary can still differ.
    estimate = ceil(((len(combined) - non_ascii) / 2 + non_ascii * 2 + 64) * 1.25)
    context = settings.effective_context_tokens
    status = (
        "unavailable"
        if context is None
        else "estimated_fit"
        if estimate + request.max_output_tokens <= context
        else "estimated_exceeded"
    )
    return RequestBudget(
        system_bytes=system_bytes,
        data_bytes=data_bytes,
        schema_bytes=schema_bytes,
        wrapper_bytes=total - system_bytes - data_bytes - schema_bytes,
        total_bytes=total,
        byte_limit=settings.max_request_bytes,
        data_byte_limit=settings.max_input_bytes,
        estimated_input_tokens=estimate,
        output_reserve_tokens=request.max_output_tokens,
        effective_context_tokens=context,
        context_status=status,
        email_bytes=json_bytes(payload["email"]) if "email" in payload else 0,
        rules_bytes=json_bytes(payload["rules"]) if "rules" in payload else 0,
        catalog_bytes=(
            json_bytes(payload["evidence_catalog"]) if "evidence_catalog" in payload else 0
        )
        + (json_bytes(payload["source_values"]) if "source_values" in payload else 0),
    )


def over_budget(value):
    return (
        value.data_bytes > value.data_byte_limit
        or value.total_bytes > value.byte_limit
        or value.context_status == "estimated_exceeded"
    )
