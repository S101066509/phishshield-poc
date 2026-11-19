# 檔案功能：讀取並驗證模型環境設定、執行上限與重連參數，提供離線設定。

"""Read the shared root .env plus explicit environment overrides; never call services."""

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.config import ENV_FILE


class EndpointSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    endpoint: str = Field(repr=False, max_length=2048)
    model: str = Field(max_length=200)
    api_key: SecretStr = Field(default=SecretStr(""), repr=False)
    provider: str = Field(default="", max_length=80, pattern=r"^[^\x00-\x1f\x7f-\x9f]*$")
    thinking: bool | None = Field(default=None, strict=True)


class LLMSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHSHIELD_LLM_",
        extra="ignore",
        frozen=True,
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
    )
    provider: str = Field(default="", max_length=80, pattern=r"^[^\x00-\x1f\x7f-\x9f]*$")
    endpoint: str = Field(default="", repr=False, max_length=2048)
    api_key: SecretStr = Field(default=SecretStr(""), repr=False)
    model_a: str = Field(default="", max_length=200)
    model_b: str = Field(default="", max_length=200)
    thinking: bool | None = None
    # 容器顯式啟用後，僅額外允許主機Docker橋接名稱使用HTTP。
    allow_docker_host_http: bool = False
    temperature: float = Field(default=0.0, ge=0, le=2, allow_inf_nan=False)
    seed: int | None = Field(default=42, ge=0, le=2147483647)
    endpoints_a: list[EndpointSettings] | None = Field(
        default=None, min_length=1, max_length=10, repr=False
    )
    endpoints_b: list[EndpointSettings] | None = Field(
        default=None, min_length=1, max_length=10, repr=False
    )
    _test_simulation: bool = PrivateAttr(default=False)
    call_timeout_seconds: float = Field(default=10, gt=0, le=120, allow_inf_nan=False)
    total_timeout_seconds: float = Field(default=30, gt=0, le=300, allow_inf_nan=False)
    max_attempts: int = Field(default=3, ge=1, le=3)
    retry_delay_seconds: float = Field(default=0.25, ge=0, le=5, allow_inf_nan=False)
    retry_backoff_multiplier: float = Field(default=2, ge=1, le=10, allow_inf_nan=False)
    retry_max_delay_seconds: float = Field(default=4, ge=0, le=30, allow_inf_nan=False)
    retry_jitter_ratio: float = Field(default=0.2, ge=0, le=1, allow_inf_nan=False)
    connection_reset_timeout_seconds: float = Field(default=2, gt=0, le=10, allow_inf_nan=False)
    max_output_tokens: int = Field(default=2048, ge=1, le=16384)
    max_input_bytes: int = Field(default=256000, ge=1, le=2000000)
    max_request_bytes: int = Field(default=256000, ge=1, le=2000000)
    # Only an explicitly known runner capacity, never a model's advertised maximum.
    effective_context_tokens: int | None = Field(default=None, ge=1024, le=2000000)
    max_output_bytes: int = Field(default=65536, ge=1, le=1000000)

    @field_validator("thinking", mode="before")
    @classmethod
    def blank_thinking_uses_service_default(cls, value):
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("temperature", "seed", mode="before")
    @classmethod
    def validate_sampling_values(cls, value, info):
        if isinstance(value, bool):
            raise ValueError("SAMPLING_VALUE_MUST_BE_NUMERIC")
        if info.field_name == "seed" and isinstance(value, str) and value.strip().lower() == "null":
            return None
        return value

    @model_validator(mode="after")
    def validate_retry_delays(self):
        if self.retry_delay_seconds > self.retry_max_delay_seconds:
            raise ValueError("RETRY_BASE_EXCEEDS_CAP")
        return self


def fake_settings(settings: LLMSettings) -> LLMSettings:
    result = settings.model_copy(
        update={
            "provider": "fake",
            "model_a": "fake-feature-v1",
            "model_b": "fake-judge-v1",
            "endpoints_a": None,
            "endpoints_b": None,
            "thinking": None,
        }
    )
    result._test_simulation = True
    return result
