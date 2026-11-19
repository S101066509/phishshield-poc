# 檔案功能：組合 LangChain 訊息與結構化模型呼叫，擷取原始回覆並管理模型工作階段。

"""LCEL model chains, shared by offline models and actual integrations."""

import json
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnableLambda
from langsmith import tracing_context
from pydantic import ValidationError

from app.domain.llm_models import TokenUsage
from app.infrastructure.llm_provider.base import (
    GenerationRequest,
    InvalidProviderOutput,
    ProviderResponse,
)

ModelSession = Callable[[GenerationRequest], AbstractAsyncContextManager[BaseChatModel]]


def to_response(value: dict) -> ProviderResponse:
    """Always validate the original content, never trust a forgiving JSON parser."""
    raw = value.get("raw") if isinstance(value, dict) else None
    if not isinstance(raw, AIMessage) or not isinstance(raw.content, str):
        raise InvalidProviderOutput
    if (
        raw.tool_calls
        or raw.invalid_tool_calls
        or any(raw.additional_kwargs.get(key) for key in ("tool_calls", "function_call", "refusal"))
    ):
        raise InvalidProviderOutput("refusal_or_tool_call")
    usage = None
    if raw.usage_metadata is not None:
        try:
            usage = TokenUsage.model_validate(
                {
                    "input_tokens": raw.usage_metadata["input_tokens"],
                    "output_tokens": raw.usage_metadata["output_tokens"],
                },
                strict=True,
            )
        except (ValidationError, KeyError, TypeError):
            raise InvalidProviderOutput("invalid_usage") from None
    finish = raw.response_metadata.get("finish_reason")
    if finish != "stop":
        raise InvalidProviderOutput(
            "output_truncated" if finish == "length" else "finish_not_stop", usage=usage
        )
    return ProviderResponse(raw.content, usage)


class LangChainProvider:
    def __init__(self, model_session: ModelSession):
        self.model_session = model_session
        self.active_sessions = 0

    async def generate_structured(self, *, request: GenerationRequest) -> ProviderResponse:
        # Fixed messages: untrusted JSON is substituted once, never used as a template.
        prompt = ChatPromptTemplate.from_messages(
            [SystemMessage(content=request.system_prompt), ("human", "{data_json}")]
        )
        with tracing_context(enabled=False):
            self.active_sessions += 1
            try:
                async with self.model_session(request) as model:
                    structured = model.with_structured_output(
                        json.loads(request.response_schema_json),
                        method="json_schema",
                        include_raw=True,
                        strict=True,
                    )
                    chain = prompt | structured | RunnableLambda(to_response, name="raw_response")
                    return await chain.ainvoke(
                        {"data_json": request.data_json},
                        config={"callbacks": [], "recursion_limit": 8},
                    )
            finally:
                self.active_sessions -= 1

    async def reset_connection(self) -> None:
        # A scoped session has already closed on success, exception or cancellation.
        # Each invocation creates a fresh client; no stale pooled connection is reused.
        if self.active_sessions:
            raise RuntimeError("MODEL_SESSION_STILL_ACTIVE")
