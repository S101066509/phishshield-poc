# 檔案功能：唯讀檢查 A／B 排序端點池，分開有效設定、可達性、備援與離線，不進行推論。
import asyncio
import json

import httpx
from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.analysis.llm.connection import (
    ConnectionConfigurationError,
    connection_key,
    endpoint_pools,
)
from app.analysis.llm.settings import LLMSettings


def _client():
    return httpx.AsyncClient(timeout=3, trust_env=False, follow_redirects=False)


async def _probe(client, settings):
    try:
        async with client.stream(
            "GET",
            settings.endpoint + "/models",
            headers={"Authorization": "Bearer " + connection_key(settings)},
        ) as response:
            if response.status_code != 200:
                return {
                    "service_reachable": True,
                    "reason_code": {
                        401: "MODEL_STATUS_AUTH_FAILED",
                        403: "MODEL_STATUS_AUTH_FAILED",
                        404: "MODEL_STATUS_UNSUPPORTED",
                        405: "MODEL_STATUS_UNSUPPORTED",
                        429: "MODEL_STATUS_RATE_LIMITED",
                    }.get(response.status_code, "MODEL_STATUS_UNAVAILABLE"),
                }
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 131072:
                    return {"service_reachable": True, "reason_code": "MODEL_STATUS_INVALID"}
            data = json.loads(body)
            items = data.get("data") if isinstance(data, dict) else None
            if not isinstance(items, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in items
            ):
                return {"service_reachable": True, "reason_code": "MODEL_STATUS_INVALID"}
            return {"service_reachable": True, "names": {item["id"] for item in items}}
    except (TimeoutError, httpx.TimeoutException):
        return {"service_reachable": False, "reason_code": "MODEL_STATUS_TIMEOUT"}
    except (ValueError, UnicodeError, RecursionError):
        return {"service_reachable": True, "reason_code": "MODEL_STATUS_INVALID"}
    except httpx.HTTPError:
        return {"service_reachable": False, "reason_code": "MODEL_STATUS_UNAVAILABLE"}


async def model_status(settings: LLMSettings | None = None) -> dict:
    result = dict(
        connected=False,
        configuration_valid=False,
        availability="unconfirmed",
        service_reachable=False,
        provider=None,
        model_a=None,
        model_b=None,
        reason_code="LLM_NOT_CONFIGURED",
        check_kind="model_availability_not_inference",
        stages={},
    )
    try:
        settings = settings or LLMSettings()
        if settings.provider.strip() == "fake":
            return result | {"reason_code": "LLM_TEST_MODE_DISABLED"}
        pools = endpoint_pools(settings)
    except (ValidationError, SettingsError):
        return result | {"reason_code": "LLM_CONFIGURATION_INVALID"}
    except ConnectionConfigurationError as exc:
        return result | {"reason_code": exc.code}
    result.update(
        configuration_valid=True,
        provider=pools["a"][0].provider,
        model_a=pools["a"][0].model_a,
        model_b=pools["b"][0].model_b,
    )
    cache = {}
    try:
        async with asyncio.timeout(4), _client() as client:
            for stage, entries in pools.items():
                item = {
                    "availability": "unconfirmed",
                    "active_endpoint_index": None,
                    "endpoint_count": len(entries),
                    "endpoints": [],
                }
                result["stages"][stage] = item
                for index, entry in enumerate(entries, 1):
                    key = (entry.endpoint, connection_key(entry))
                    if key not in cache:
                        cache[key] = await _probe(client, entry)
                    probe = cache[key]
                    reachable = probe["service_reachable"]
                    result["service_reachable"] |= reachable
                    model_id = entry.model_a if stage == "a" else entry.model_b
                    if "names" in probe:
                        availability = "available" if model_id in probe["names"] else "missing"
                        code = (
                            "MODEL_STATUS_READY"
                            if availability == "available"
                            else "MODEL_STATUS_MODEL_MISSING"
                        )
                    else:
                        availability = "unconfirmed" if reachable else "offline"
                        code = probe["reason_code"]
                    item["endpoints"].append(
                        dict(
                            index=index,
                            availability=availability,
                            service_reachable=reachable,
                            reason_code=code,
                        )
                    )
                    if availability == "available":
                        item.update(availability="available", active_endpoint_index=index)
                        result["model_" + stage] = model_id
                        break
                else:
                    states = {e["availability"] for e in item["endpoints"]}
                    item["availability"] = (
                        "offline"
                        if states == {"offline"}
                        else "unconfirmed"
                        if "unconfirmed" in states or "offline" in states
                        else "missing"
                    )
            states = {item["availability"] for item in result["stages"].values()}
            if states == {"available"}:
                return result | dict(
                    connected=True, availability="available", reason_code="MODEL_STATUS_READY"
                )
            availability = (
                "offline"
                if "offline" in states
                else "unconfirmed"
                if "unconfirmed" in states
                else "missing"
            )
            codes = [
                e["reason_code"]
                for s in result["stages"].values()
                for e in s["endpoints"]
                if e["availability"] != "available"
            ]
            code = (
                "MODEL_STATUS_OFFLINE"
                if availability == "offline"
                else next(
                    (c for c in codes if c != "MODEL_STATUS_READY"), "MODEL_STATUS_UNAVAILABLE"
                )
            )
            return result | dict(availability=availability, reason_code=code)
    except (TimeoutError, httpx.TimeoutException):
        return result | dict(reason_code="MODEL_STATUS_TIMEOUT")
