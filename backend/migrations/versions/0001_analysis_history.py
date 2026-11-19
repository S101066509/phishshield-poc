# 檔案功能：建立三張分析歷史資料表、狀態約束與索引，提供可逆的首版資料庫 migration。

import sqlalchemy as sa
from alembic import op

revision = "0001_analysis_history"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("classification", sa.String(16)),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING','PROCESSING','COMPLETED','FAILED')"),
        sa.CheckConstraint(
            "classification IS NULL OR classification IN ('SAFE','SUSPICIOUS','PHISHING','UNKNOWN')"
        ),
        sa.CheckConstraint(
            "(status IN ('PENDING','PROCESSING') AND classification IS NULL) OR "
            "(status='FAILED' AND classification='UNKNOWN') OR "
            "(status='COMPLETED' AND classification IS NOT NULL)"
        ),
    )
    for name, columns in [
        ("ix_analyses_created_id", ["created_at", "id"]),
        ("ix_analyses_status", ["status"]),
        ("ix_analyses_classification", ["classification"]),
    ]:
        op.create_index(name, "analyses", columns)
    op.create_table(
        "analysis_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Uuid(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(80), nullable=False),
        sa.Column("rule_version", sa.String(24), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
    )
    op.create_index("ix_analysis_findings_analysis_id", "analysis_findings", ["analysis_id"])
    op.create_table(
        "analysis_evidence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.Uuid(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("location_ref", sa.String(120), nullable=False),
        sa.Column("evidence_type", sa.String(16), nullable=False),
        sa.Column("sanitized_excerpt", sa.String(80), nullable=False),
        sa.Column("retained_content", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_analysis_evidence_analysis_id", "analysis_evidence", ["analysis_id"])


def downgrade():
    op.drop_table("analysis_evidence")
    op.drop_table("analysis_findings")
    op.drop_table("analyses")
