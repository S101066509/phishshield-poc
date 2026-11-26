# 檔案功能：依明確環境設定建立 ChatOpenAI 連接，每次嘗試關閉所擁有的 SDK Client。

"""Explicitly configured LangChain integration; credentials never enter chain input."""

from contextlib import asynccontextmanager

import httpx2
from langchain_openai import ChatOpenAI
from openai import AsyncOpenAI, OpenAI
from pydantic import Field

from app.analysis.llm.connection import connection_key, connection_settings
from app.analysis.llm.settings import LLMSettings, OutputTokenParameter
from app.infrastructure.llm_provider.base import GenerationRequest
from app.infrastructure.llm_provider.langchain import LangChainProvider


class EndpointChatOpenAI(ChatOpenAI):
    """Keep the endpoint's explicit wire contract after LangChain normalizes token names."""

    output_token_parameter: OutputTokenParameter = Field(
        default="max_completion_tokens", exclude=True
    )

    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        # 上游SDK會把max_tokens正規化成新欄位；在最終序列化邊界只保留端點接受的一欄。
        # 不更動上限數值、不自動重送，也不根據模型名稱改變協定。
        if "max_completion_tokens" in payload:
            limit = payload.pop("max_completion_tokens")
            payload[self.output_token_parameter] = limit
        return payload


class OpenAIProvider(LangChainProvider):
    def __init__(self, settings: LLMSettings):
        self.settings = connection_settings(settings)
        super().__init__(self._model_session)

    def _new_sync_client(self):
        return httpx2.Client(trust_env=False, follow_redirects=False)

    def _new_async_client(self):
        return httpx2.AsyncClient(trust_env=False, follow_redirects=False)

    @asynccontextmanager
    async def _model_session(self, request: GenerationRequest):
        # Both SDK clients are owned by this attempt and closed in all exit paths.
        # Explicit clients also prevent implicit SDK retries / proxy / default endpoint.
        options = dict(
            api_key=connection_key(self.settings),
            base_url=self.settings.endpoint,
            timeout=self.settings.call_timeout_seconds,
            max_retries=0,
            default_headers={"X-Client-Request-Id": request.request_id},
        )
        # Chat Completions uses reasoning_effort, not Ollama's native `think` field.
        # Omit it by default so models without this optional capability keep working.
        thinking_options = (
            {}
            if self.settings.thinking is None
            else {"reasoning_effort": "medium" if self.settings.thinking else "none"}
        )
        sampling_options = {"temperature": self.settings.temperature}
        if self.settings.seed is not None:
            sampling_options["seed"] = self.settings.seed
        with self._new_sync_client() as sync_http:
            async with self._new_async_client() as async_http:
                with OpenAI(http_client=sync_http, **options) as sync_sdk:
                    async with AsyncOpenAI(http_client=async_http, **options) as async_sdk:
                        yield EndpointChatOpenAI(
                            model=request.model_id,
                            api_key=connection_key(self.settings),
                            base_url=self.settings.endpoint,
                            max_tokens=request.max_output_tokens,
                            output_token_parameter=self.settings.output_token_parameter,
                            max_retries=0,
                            timeout=self.settings.call_timeout_seconds,
                            streaming=False,
                            disable_streaming=True,
                            use_responses_api=False,
                            cache=False,
                            verbose=False,
                            client=sync_sdk.chat.completions,
                            root_client=sync_sdk,
                            async_client=async_sdk.chat.completions,
                            root_async_client=async_sdk,
                            **sampling_options,
                            **thinking_options,
                        )
