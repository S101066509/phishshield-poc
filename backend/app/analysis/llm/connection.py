# 檔案功能：統一相容模型端點的傳輸政策與設定解析，不依服務商標籤選擇協定。

from urllib.parse import urlsplit, urlunsplit

from app.analysis.llm.settings import LLMSettings
from app.domain.llm_models import provider_label

SDK_PLACEHOLDER_KEY = "not-configured"


class ConnectionConfigurationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def normalize_endpoint(value: str, *, allow_docker_host_http: bool = False) -> str:
    if not value.strip():
        raise ConnectionConfigurationError("LLM_NOT_CONFIGURED")
    try:
        # urlsplit silently removes some controls; reject them before parsing.
        if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
            raise ValueError
        if "\\" in value or "?" in value or "#" in value:
            raise ValueError
        url = urlsplit(value)
        local_http_hosts = {"localhost", "127.0.0.1", "::1"}
        if allow_docker_host_http is True:
            local_http_hosts.add("host.docker.internal")
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or "@" in url.netloc
            or url.netloc.endswith(":")
            or (url.port is not None and not 1 <= url.port <= 65535)
            or (url.scheme == "http" and url.hostname not in local_http_hosts)
        ):
            raise ValueError
        return urlunsplit((url.scheme, url.netloc, url.path.rstrip("/"), "", ""))
    except ValueError:
        raise ConnectionConfigurationError("LLM_CONFIGURATION_INVALID") from None


def connection_settings(settings: LLMSettings) -> LLMSettings:
    endpoint = normalize_endpoint(
        settings.endpoint, allow_docker_host_http=settings.allow_docker_host_http
    )
    if not settings.model_a.strip() or not settings.model_b.strip():
        raise ConnectionConfigurationError("LLM_CONFIGURATION_INVALID")
    try:
        label = provider_label(settings.provider)
    except ValueError:
        raise ConnectionConfigurationError("LLM_CONFIGURATION_INVALID") from None
    return settings.model_copy(update={"endpoint": endpoint, "provider": label})


def connection_key(settings: LLMSettings) -> str:
    # Explicit placeholder prevents SDK fallback to OPENAI_API_KEY or another credential.
    value = settings.api_key.get_secret_value()
    return value if value.strip() else SDK_PLACEHOLDER_KEY


def endpoint_pools(settings: LLMSettings) -> dict[str, list[LLMSettings]]:
    pools = {}
    for stage in ("a", "b"):
        entries = getattr(settings, "endpoints_" + stage)
        if entries is None:
            pools[stage] = [connection_settings(settings)]
            continue
        resolved = []
        for entry in entries:
            if entry.provider.strip() == "fake":
                raise ConnectionConfigurationError("LLM_TEST_MODE_DISABLED")
            item = settings.model_copy(
                update={
                    "provider": entry.provider,
                    "endpoint": entry.endpoint,
                    "api_key": entry.api_key,
                    "model_a": entry.model,
                    "model_b": entry.model,
                    "thinking": entry.thinking
                    if "thinking" in entry.model_fields_set
                    else settings.thinking,
                    "endpoints_a": None,
                    "endpoints_b": None,
                }
            )
            resolved.append(connection_settings(item))
        pools[stage] = resolved
    return pools
