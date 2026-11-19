# 檔案功能：以受控交易保存去敏化分析資料、規則與證據，提供分頁及單筆歷史查詢。

from datetime import UTC, date, datetime, time
from uuid import UUID
from zoneinfo import ZoneInfo

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.config import AppSettings
from app.domain.versions import DATABASE_SCHEMA_VERSION
from app.infrastructure.db.models import AnalysisRow, EvidenceRow, FindingRow


class HistoryRepository:
    def __init__(self, settings: AppSettings):
        url = settings.database_url.get_secret_value()
        if not url.startswith("postgresql+psycopg://"):
            raise ValueError("POSTGRESQL_REQUIRED")
        self.schema = settings.database_schema
        self.engine = create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=0,
            pool_timeout=3,
            connect_args={
                "connect_timeout": 3,
                "options": f"-c search_path={self.schema} -c statement_timeout=5000",
            },
            echo=False,
        )

    async def close(self):
        await self.engine.dispose()

    async def health(self):
        async with self.engine.connect() as connection:
            value = await connection.exec_driver_sql("SELECT version_num FROM alembic_version")
            if value.scalar_one_or_none() != DATABASE_SCHEMA_VERSION:
                from sqlalchemy.exc import SQLAlchemyError

                raise SQLAlchemyError("DATABASE_MIGRATION_REQUIRED")

    async def save(
        self,
        payload: dict,
        source: str,
        content_hash: str | None,
        source_document: dict | None = None,
    ):
        now = datetime.now(UTC)
        created_at = (
            datetime.fromisoformat(payload["created_at"]) if payload.get("created_at") else now
        )
        completed_at = (
            datetime.fromisoformat(payload["completed_at"]) if payload.get("completed_at") else None
        )
        async with AsyncSession(self.engine) as session, session.begin():
            row = AnalysisRow(
                id=UUID(payload["analysis_id"]),
                source=source,
                status=payload["status"],
                classification=payload["final_classification"],
                content_hash=content_hash,
                created_at=created_at,
                completed_at=completed_at,
                result=payload,
                source_document=source_document,
            )
            session.add(row)
            await session.flush()
            for finding in payload["rule_findings"]:
                session.add(
                    FindingRow(
                        analysis_id=row.id,
                        **{
                            key: finding[key]
                            for key in (
                                "rule_id",
                                "rule_version",
                                "category",
                                "severity",
                                "evidence_refs",
                            )
                        },
                    )
                )
            for item in payload["evidence"]:
                session.add(
                    EvidenceRow(
                        analysis_id=row.id,
                        location_ref=item["ref"],
                        evidence_type=item["kind"],
                        sanitized_excerpt="[CONTENT_NOT_RETAINED]",
                        retained_content=False,
                    )
                )
        return payload

    async def get(self, identifier: UUID):
        async with AsyncSession(self.engine) as session:
            row = await session.get(AnalysisRow, identifier)
            if row is None:
                return None
            return row.result | {
                "created_at": row.created_at.isoformat(),
                "started_at": row.result.get("started_at"),
                "completed_at": row.result.get("completed_at"),
                "latency_ms": row.result.get("latency_ms")
                if row.result.get("latency_scope")
                else None,
                "latency_scope": row.result.get("latency_scope"),
                "source_document": row.source_document,
            }

    async def list(
        self,
        page: int,
        page_size: int,
        *,
        query: str | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
    ):
        filters = []
        if query:
            fields = [
                AnalysisRow.source_document["parsed"]["subject"].as_string(),
                AnalysisRow.source_document["parsed"]["sender"].as_string(),
                AnalysisRow.source_document["parsed"]["body_text"].as_string(),
                AnalysisRow.source_document["raw_text"].as_string(),
                AnalysisRow.result["analysis_explanation"]["model"]["rationale"].as_string(),
            ]
            filters.append(or_(*(field.icontains(query, autoescape=True) for field in fields)))
        zone = ZoneInfo("Asia/Taipei")
        if date_from:
            filters.append(AnalysisRow.created_at >= datetime.combine(date_from, time.min, zone))
        if date_to:
            filters.append(AnalysisRow.created_at <= datetime.combine(date_to, time.max, zone))
        async with AsyncSession(self.engine) as session:
            total = await session.scalar(
                select(func.count()).select_from(AnalysisRow).where(*filters)
            )
            rows = (
                (
                    await session.execute(
                        select(
                            AnalysisRow.id,
                            AnalysisRow.created_at,
                            AnalysisRow.status,
                            AnalysisRow.classification,
                            AnalysisRow.source_document["parsed"]["subject"]
                            .as_string()
                            .label("subject"),
                            AnalysisRow.source_document["parsed"]["sender"]
                            .as_string()
                            .label("sender"),
                            AnalysisRow.result["simulation"].as_boolean().label("simulation"),
                            AnalysisRow.result["model_analysis"].label("model_analysis"),
                            AnalysisRow.result["analysis_reliability"].label(
                                "analysis_reliability"
                            ),
                            AnalysisRow.result["coverage"].label("coverage"),
                            AnalysisRow.result["rule_signal_summary"].label("rule_signal_summary"),
                            AnalysisRow.result["review_required"]
                            .as_boolean()
                            .label("review_required"),
                        )
                        .where(*filters)
                        .order_by(AnalysisRow.created_at.desc(), AnalysisRow.id.desc())
                        .offset((page - 1) * page_size)
                        .limit(page_size)
                    )
                )
                .mappings()
                .all()
            )
            return dict(
                page=page,
                page_size=page_size,
                total=total,
                items=[
                    {
                        "analysis_id": str(row["id"]),
                        "created_at": row["created_at"].isoformat(),
                        "status": row["status"],
                        "subject": row["subject"],
                        "sender": row["sender"],
                        "final_classification": row["classification"],
                        "simulation": row["simulation"] if row["simulation"] is not None else False,
                        "model_analysis": row["model_analysis"],
                        "analysis_reliability": row["analysis_reliability"],
                        "coverage": row["coverage"],
                        "rule_signal_summary": row["rule_signal_summary"],
                        "review_required": row["review_required"]
                        if row["review_required"] is not None
                        else True,
                    }
                    for row in rows
                ],
            )
