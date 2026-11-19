# 檔案功能：定義模型請求、回覆、錯誤類型與可替換的非同步供應商介面。

from dataclasses import dataclass, field
from typing import Protocol
from uuid import uuid4

from app.domain.llm_models import OutputDiagnostic, TokenUsage


@dataclass(frozen=True)
class GenerationRequest:
    system_prompt: str
    data_json: str
    response_schema_json: str
    model_id: str
    max_output_tokens: int
    # Stable across retries of ONE stage, distinct across A/B and separate analyses.
    request_id: str = field(default_factory=lambda: uuid4().hex)


@dataclass(frozen=True)
class ProviderResponse:
    json_text: str
    usage: TokenUsage | None = None


class TransientProviderError(Exception):
    """Adapter maps rate limits / temporary transport failures to this type."""

    def __init__(self, message="", *, retry_after_seconds: float | None = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class ProviderDisconnectedError(TransientProviderError):
    """The failed session must be discarded before another generation attempt."""


class PermanentProviderError(Exception):
    """Authentication / unsupported requests: never retry."""


class InvalidProviderOutput(Exception):
    """Refusal, tool calls or malformed framework output; never retry as transport failure."""

    def __init__(self, reason="invalid_response", *, usage=None):
        self.usage = usage if isinstance(usage, TokenUsage) else None
        self.diagnostic = OutputDiagnostic(
            reason=reason,
            category="output_truncated" if reason == "output_truncated" else "core_schema",
            finish_reason="length" if reason == "output_truncated" else "other",
        )
        super().__init__("LLM_OUTPUT_INVALID")


class LLMProvider(Protocol):
    # Implementations must be cancellation-cooperative and do no blocking I/O.
    # This interface exposes no tools, callbacks, shell, DB or URL-fetch operations.
    async def generate_structured(self, *, request: GenerationRequest) -> ProviderResponse: ...

    async def reset_connection(self) -> None:
        """Discard failed transport; next generation creates a fresh connection lazily.

        Must be cancellation-cooperative. generate_structured must abort/close its active
        response in finally on cancellation. Do not put another retry loop in the adapter.
        """
        ...
