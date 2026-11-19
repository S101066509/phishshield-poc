# 檔案功能：提供 LangChain 離線模型與腳本回覆，測試流程而不呼叫真實 API。

"""Offline deterministic stub, NOT a phishing detector or a real model."""

import asyncio
import json
from collections import deque
from collections.abc import Iterable
from contextlib import asynccontextmanager

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda
from pydantic import Field

from app.infrastructure.llm_provider.base import GenerationRequest, ProviderResponse
from app.infrastructure.llm_provider.langchain import LangChainProvider


class OfflineChatModel(BaseChatModel):
    """A real LangChain model interface with scripted, local responses only."""

    request: GenerationRequest = Field(exclude=True)
    reply: object = Field(exclude=True)

    @property
    def _llm_type(self):
        return "phishshield-offline"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise RuntimeError("ASYNC_MODEL_ONLY")

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        response = await self.reply(self.request)
        usage = None
        if response.usage is not None:
            usage = response.usage.model_dump() | {
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens
            }
        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(
                        content=response.json_text,
                        usage_metadata=usage,
                        response_metadata={"finish_reason": "stop"},
                    )
                )
            ]
        )

    def with_structured_output(self, schema, **kwargs):
        # Offline data intentionally includes malformed JSON for regression tests.
        # Return original content through the same LCEL model / response path.
        return self | RunnableLambda(lambda raw: {"raw": raw}, name="offline_raw")


class FakeProvider(LangChainProvider):
    def __init__(
        self, responses: Iterable[ProviderResponse | Exception] | None = None, *, delay: float = 0
    ):
        super().__init__(self._model_session)
        self.responses = deque(responses) if responses is not None else None
        self.delay = delay
        self.requests: list[GenerationRequest] = []
        self.connection_resets = 0

    async def reset_connection(self) -> None:
        await super().reset_connection()
        # No sockets exist in this stub; observable hook for recovery tests.
        self.connection_resets += 1

    async def generate_structured(self, *, request: GenerationRequest) -> ProviderResponse:
        self.requests.append(request)
        return await super().generate_structured(request=request)

    @asynccontextmanager
    async def _model_session(self, request):
        yield OfflineChatModel(request=request, reply=self._reply, cache=False)

    async def _reply(self, request: GenerationRequest) -> ProviderResponse:
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.responses is not None:
            if not self.responses:
                raise RuntimeError("FAKE_RESPONSES_EXHAUSTED")
            response = self.responses.popleft()
            if isinstance(response, Exception):
                raise response
            return response
        schema = json.loads(request.response_schema_json)
        payload = json.loads(request.data_json)
        if schema.get("properties", {}).get("contract", {}).get("const") == "event_extraction_1":
            # A simulation is explicitly incomplete, not a claim of semantic extraction.
            data = {
                "contract": "event_extraction_1",
                "status": "incomplete",
                "events": [],
                "relations": [],
                "inspected_refs": list(payload["evidence_catalog"])[:1],
            }
        elif payload.get("contract") == "event_handoff_1":
            from typing import get_args

            from app.domain.event_models import EventReason

            slots = dict.fromkeys(get_args(EventReason))
            slots["SIMULATED_ANALYSIS"] = {"source_id": None, "evidence_refs": []}
            data = {
                "decision": {
                    "classification": "UNKNOWN",
                    "reason_slots": slots,
                    "uncertainty_codes": ["SIMULATION"],
                }
            }
        elif "decision" in schema["properties"]:
            from typing import get_args

            from app.domain.handoff_models import Reason

            slots = dict.fromkeys(get_args(Reason))
            slots["SIMULATED_ANALYSIS"] = {"observation_id": None, "evidence_refs": []}
            data = {
                "decision": {
                    "classification": "UNKNOWN",
                    "reason_slots": slots,
                    "uncertainty_codes": ["SIMULATION"],
                }
            }
        elif "reason_supports" in schema["properties"]:
            data = dict(
                classification="UNKNOWN",
                reason_supports=[
                    dict(reason_code="SIMULATED_ANALYSIS", observation_id=None, evidence_refs=[])
                ],
                uncertainty_codes=["SIMULATION"],
                rationale="離線模擬，未執行真實模型判讀。",
                explanations=[],
            )
        elif "supporting_observation_ids" in schema["properties"]:
            data = dict(
                classification="UNKNOWN",
                reason_codes=["SIMULATED_ANALYSIS"],
                supporting_observation_ids=[],
                evidence_refs=[],
                uncertainty_codes=["SIMULATION"],
                rationale="離線模擬，未執行真實模型判讀。",
                explanations=[],
            )
        elif "features" in schema["properties"]:
            data = dict(
                features=[],
                suspicious_url_refs=[],
                social_engineering_indicators=[],
                uncertainties=["FAKE_PROVIDER_NO_MODEL_ANALYSIS"],
            )
        else:
            data = dict(
                classification="UNKNOWN",
                reason_codes=["FAKE_PROVIDER_NO_MODEL_ANALYSIS"],
                evidence_refs=[],
                uncertainties=["FAKE_PROVIDER_NO_MODEL_ANALYSIS"],
                confidence=None,
            )
        if "observations" in schema.get("required", []):
            from app.domain.handoff_models import KINDS

            payload = json.loads(request.data_json)
            refs = list(payload["evidence_catalog"])[:1]
            mail = payload["email"]
            if "features" not in schema["properties"]:
                data = {}
            data["observations"] = [
                dict(
                    kind=kind,
                    assessment=(
                        "not_applicable"
                        if (kind == "url_deception" and not mail["urls"])
                        or (
                            kind == "authentication"
                            and not any(
                                mail["headers"].get(name)
                                for name in (
                                    "authentication-results",
                                    "received-spf",
                                    "dkim-signature",
                                )
                            )
                        )
                        else "uncertain"
                    ),
                    evidence_refs=refs,
                )
                for kind in KINDS
            ]
            if schema["properties"]["observations"].get("type") == "object":
                data["observations"] = {
                    item["kind"]: {
                        "assessment": item["assessment"],
                        "evidence_refs": []
                        if item["assessment"] == "not_applicable"
                        else item["evidence_refs"],
                    }
                    for item in data["observations"]
                }
        return ProviderResponse(json.dumps(data))
