# 檔案功能：讀取本機 API、資料庫與分析期限設定，隱藏資料庫連線資訊。

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PHISHSHIELD_",
        extra="ignore",
        frozen=True,
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
    )
    database_url: SecretStr = Field(
        default=SecretStr("postgresql+psycopg://phishshield@127.0.0.1:55432/phishshield"),
        repr=False,
    )
    database_schema: str = Field(default="public", pattern=r"^[a-z][a-z0-9_]{0,62}$")
    analysis_timeout_seconds: float = Field(default=45, gt=0, le=300, allow_inf_nan=False)
    reconciliation_timeout_seconds: float = Field(default=1, gt=0, le=5, allow_inf_nan=False)
    max_request_bytes: int = Field(default=2100000, ge=1024, le=3000000)
    enable_test_simulation: bool = False
