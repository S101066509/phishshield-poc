# 檔案功能：分類網路、SDK 與模型回覆錯誤，決定可否重試及是否清理連線。

"""Transport error classification for current httpx dependency and future adapters."""

import errno
import socket
import ssl
from dataclasses import dataclass
from typing import get_args

import httpx
import httpx2
import openai

from app.domain.llm_models import (
    OutputDiagnostic,
    TimeoutKind,
    TokenUsage,
    TransportDiagnostic,
    TransportParameter,
)
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
    timeout_kind: TimeoutKind | None = None


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


def transport_diagnostic(exc: Exception, *, timeout_kind=None) -> TransportDiagnostic | None:
    """Classify SDK/transport types and exact allowed parameters without reading error prose."""
    if isinstance(
        exc,
        (
            InvalidProviderOutput,
            openai.LengthFinishReasonError,
            openai.ContentFilterFinishReasonError,
        ),
    ):
        return None
    causes, seen = [], set()
    cause = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        causes.append(cause)
        cause = cause.__cause__ or cause.__context__
    status = None
    if isinstance(exc, openai.APIStatusError):
        value = exc.status_code
        status = value if type(value) is int and 100 <= value <= 599 else None
    elif isinstance(exc, (httpx.HTTPStatusError, httpx2.HTTPStatusError)):
        value = exc.response.status_code
        status = value if type(value) is int and 100 <= value <= 599 else None
    parameter = getattr(exc, "param", None) if isinstance(exc, openai.APIError) else None
    parameter = (
        parameter
        if isinstance(parameter, str) and parameter in get_args(TransportParameter)
        else None
    )
    phase = timeout_kind if timeout_kind in get_args(TimeoutKind) else None
    if phase is None:
        for error, name in (
            ((httpx.ConnectTimeout, httpx2.ConnectTimeout), "connect"),
            ((httpx.PoolTimeout, httpx2.PoolTimeout), "pool"),
            ((httpx.ReadTimeout, httpx2.ReadTimeout), "read"),
            ((httpx.WriteTimeout, httpx2.WriteTimeout), "write"),
        ):
            if any(isinstance(value, error) for value in causes):
                phase = name
                break
    if phase is None and isinstance(
        exc, (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException, openai.APITimeoutError)
    ):
        phase = "unspecified"
    if phase is not None:
        category = "timeout"
    elif any(isinstance(value, ssl.SSLCertVerificationError) for value in causes):
        category = "tls_error"
    elif status is not None:
        category = {
            400: "bad_request",
            401: "authentication",
            403: "permission",
            404: "not_found",
            422: "unprocessable_request",
            429: "rate_limit",
        }.get(status, "server_error" if status >= 500 else "http_status")
    elif any(isinstance(value, socket.gaierror) for value in causes):
        category = "dns_error"
    elif any(
        isinstance(value, (httpx.RemoteProtocolError, httpx2.RemoteProtocolError))
        for value in causes
    ):
        category = "protocol_error"
    elif any(
        isinstance(
            value,
            (
                ConnectionError,
                openai.APIConnectionError,
                ProviderDisconnectedError,
                httpx.NetworkError,
                httpx2.NetworkError,
                httpx.ProxyError,
                httpx2.ProxyError,
            ),
        )
        for value in causes
    ):
        category = "connection_error"
    elif isinstance(exc, (openai.APIError, TransientProviderError)):
        category = "provider_error"
    else:
        category = "unknown"
    return TransportDiagnostic(
        category=category, http_status=status, parameter=parameter, timeout_phase=phase
    )


def recovery_policy(exc: Exception) -> RecoveryPolicy:
    # Certificate / protocol / authentication errors must never disable TLS or retry blindly.
    cause = exc
    seen = set()
    causes = []
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        causes.append(cause)
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
    # 已送出／等待回覆的逾時可能仍在遠端生成，不能當成尚未連線而盲目重抽。
    # SDK會包裝transport例外；只讀型別／cause，不保存例外文字或臆測生成進度。
    for cause in causes:
        if isinstance(cause, (httpx.PoolTimeout, httpx2.PoolTimeout)):
            return RecoveryPolicy("LLM_TIMEOUT", True, timeout_kind="pool")
        if isinstance(cause, (httpx.ConnectTimeout, httpx2.ConnectTimeout)):
            return RecoveryPolicy("LLM_TIMEOUT", True, True, timeout_kind="connect")
        if isinstance(cause, (httpx.ReadTimeout, httpx2.ReadTimeout)):
            return RecoveryPolicy("LLM_TIMEOUT", False, True, timeout_kind="read")
        if isinstance(cause, (httpx.WriteTimeout, httpx2.WriteTimeout)):
            return RecoveryPolicy("LLM_TIMEOUT", False, True, timeout_kind="write")
    if isinstance(
        exc, (TimeoutError, httpx.TimeoutException, httpx2.TimeoutException, openai.APITimeoutError)
    ):
        return RecoveryPolicy("LLM_TIMEOUT", False, True, timeout_kind="unspecified")
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
