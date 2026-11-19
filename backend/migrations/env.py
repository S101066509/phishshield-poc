# 檔案功能：以環境設定或注入連線執行 Alembic migration，支援隔離測試 schema。

from alembic import context
from sqlalchemy import create_engine

from app.config import AppSettings
from app.infrastructure.db.models import Base

settings = context.config.attributes.get("settings") or AppSettings()


def run(connection):
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        version_table_schema=settings.database_schema,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("ONLINE_MIGRATIONS_REQUIRED")
else:
    provided = context.config.attributes.get("connection")
    if provided is not None:
        run(provided)
    else:
        engine = create_engine(
            settings.database_url.get_secret_value(),
            connect_args={
                "connect_timeout": 3,
                "options": f"-c search_path={settings.database_schema}",
            },
        )
        try:
            with engine.connect() as connection:
                run(connection)
        finally:
            engine.dispose()
