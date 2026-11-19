# 檔案功能：分類網路、SDK 與模型回覆錯誤，決定可否重試及是否清理連線。

"""Transport error classification for current httpx dependency and future adapters."""

import errno
import socket
import ssl
from dataclasses import dataclass

import httpx
import httpx2
import openai

from app.domain.llm_models import OutputDiagnostic, TokenUsage
from app.infrastructure.llm_provider.base import (
    InvalidProviderOutput,
    ProviderDisconnectedError,
    TransientProviderError,
)


@dataclass(frozen=True)
class RecoveryPolicy:
    code: str
    retryable: bool
    reset_connection: bool = False
    retry_after_seconds: float | None = None


def output_diagnostic(exc: Exception) -> OutputDiagnostic | None:
    if isinstance(exc, InvalidProviderOutput):
        return exc.diagnostic
    if isinstance(exc, openai.LengthFinishReasonError):
        return OutputDiagnostic(reason="output_truncated")
    if isinstance(exc, openai.ContentFilterFinishReasonError):
        return OutputDiagnostic(reason="refusal_or_tool_call")
    return None


def provider_usage(exc):
    value = getattr(exc, "usage", None)
    if isinstance(value, TokenUsage):
        return value
    if isinstance(exc, openai.LengthFinishReasonError):
        usage = getattr(getattr(exc, "completion", None), "usage", None)
        try:
            return TokenUsage(
                input_tokens=usage.prompt_tokens, output_tokens=usage.completion_tokens
            )
        except (ValueError, TypeError, AttributeError):
            return None
    return None


def recovery_policy(exc: Exception) -> RecoveryPolicy:
    # Certificate / protocol / authentication errors must never disable TLS or retry blindly.
    cause = exc
    seen = set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, ssl.SSLCertVerificationError):
            return RecoveryPolicy("LLM_PROVIDER_FAILED", False)
        cause = cause.__cause__ or cause.__context__
    if isinstance(exc, InvalidProviderOutput):
        return RecoveryPolicy("LLM_OUTPUT_INVALID", False)
    if isinstance(exc, (openai.LengthFinishReasonError, openai.ContentFilterFinishReasonError)):
        return RecoveryPolicy("LLM_OUTPUT_INVALID", False)
    if isinstance(exc, openai.APIStatusError):
        if exc.status_code in {401, 403}:
            return RecoveryPolicy("LLM_AUTH_FAILED", False)
        if exc.status_code == 429 or exc.status_code in {500, 502, 503, 504}:
            hint = exc.response.headers.get("retry-after")
            try:
                retry_after = float(hint) if hint is not None else None
            except ValueError:
                retry_after = float("inf")  # Never retry early on an unhandled delay hint.
            return RecoveryPolicy("LLM_PROVIDER_FAILED", True, retry_after_seconds=retry_after)
        return RecoveryPolicy("LLM_PROVIDER_FAILED", False)
    if isinstance(exc, (httpx.PoolTimeout, httpx2.PoolTimeout)):
        # Pool saturation does not mean an established connection is broken.
        return RecoveryPolicy("LLM_TIMEOUT", True)
    if isinstance(
        exc, (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException, openai.APITimeoutError)
    ):
        return RecoveryPolicy("LLM_TIMEOUT", True, True)
    if isinstance(exc, openai.APIConnectionError):
        return RecoveryPolicy("LLM_CONNECTION_LOST", True, True)
    if isinstance(exc, socket.gaierror):
        if exc.errno == socket.EAI_AGAIN:
            return RecoveryPolicy("LLM_CONNECTION_LOST", True, True)
        return RecoveryPolicy("LLM_PROVIDER_FAILED", False)
    if isinstance(exc, OSError) and exc.errno in {
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.ENETRESET,
        errno.EHOSTUNREACH,
        errno.ENOTCONN,
        errno.ECONNABORTED,
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.EPIPE,
    }:
        return RecoveryPolicy("LLM_CONNECTION_LOST", True, True)
    if isinstance(
        exc,
        (
            ConnectionError,
            ProviderDisconnectedError,
            httpx.NetworkError,
            httpx.RemoteProtocolError,
            httpx.ProxyError,
            httpx2.NetworkError,
            httpx2.RemoteProtocolError,
            httpx2.ProxyError,
        ),
    ):
        return RecoveryPolicy(
            "LLM_CONNECTION_LOST", True, True, getattr(exc, "retry_after_seconds", None)
        )
    if isinstance(exc, TransientProviderError):
        return RecoveryPolicy(
            "LLM_PROVIDER_FAILED", True, retry_after_seconds=exc.retry_after_seconds
        )
    return RecoveryPolicy("LLM_PROVIDER_FAILED", False)
