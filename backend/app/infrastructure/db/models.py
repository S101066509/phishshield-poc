# 檔案功能：定義分析、規則與去敏化證據的關聯資料表及狀態約束。

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AnalysisRow(Base):
    __tablename__ = "analyses"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING','PROCESSING','COMPLETED','FAILED')"),
        CheckConstraint(
            "classification IS NULL OR classification IN ('SAFE','SUSPICIOUS','PHISHING','UNKNOWN')"
        ),
        CheckConstraint(
            "(status IN ('PENDING','PROCESSING') AND classification IS NULL) OR "
            "(status='FAILED' AND classification='UNKNOWN') OR "
            "(status='COMPLETED' AND classification IS NOT NULL)"
        ),
        Index("ix_analyses_created_id", "created_at", "id"),
        Index("ix_analyses_status", "status"),
        Index("ix_analyses_classification", "classification"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    classification: Mapped[str | None] = mapped_column(String(16))
    content_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict] = mapped_column(JSON)
    source_document: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class FindingRow(Base):
    __tablename__ = "analysis_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(80))
    rule_version: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    evidence_refs: Mapped[list] = mapped_column(JSON)


class EvidenceRow(Base):
    __tablename__ = "analysis_evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[UUID] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    location_ref: Mapped[str] = mapped_column(String(120))
    evidence_type: Mapped[str] = mapped_column(String(16))
    sanitized_excerpt: Mapped[str] = mapped_column(String(80))
    retained_content: Mapped[bool] = mapped_column(Boolean, default=False)
