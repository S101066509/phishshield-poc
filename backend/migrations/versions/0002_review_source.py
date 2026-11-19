# 檔案功能：新增可空的人工覆核原文欄位，保留舊紀錄並支援可逆 migration。

import sqlalchemy as sa
from alembic import op

revision = "0002_review_source"
down_revision = "0001_analysis_history"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("analyses", sa.Column("source_document", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("analyses", "source_document")
