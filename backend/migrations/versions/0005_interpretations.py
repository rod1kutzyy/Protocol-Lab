"""Immutable protocol interpretations and per-message decoding results."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005_interpretations"
down_revision = "0004_framing"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "interpretation_versions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("model_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("parent_id", sa.Uuid(), sa.ForeignKey("interpretation_versions.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    for name in ("model_id", "project_id"):
        op.create_index(f"ix_interpretation_versions_{name}", "interpretation_versions", [name])
    op.create_table(
        "interpretation_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("framing_run_id", sa.Uuid(), sa.ForeignKey("framing_runs.id"), nullable=False),
        sa.Column(
            "version_id", sa.Uuid(), sa.ForeignKey("interpretation_versions.id"), nullable=False
        ),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    for name in ("framing_run_id", "version_id"):
        op.create_index(f"ix_interpretation_runs_{name}", "interpretation_runs", [name])
    op.create_table(
        "interpretation_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("interpretation_runs.id"), nullable=False),
        sa.Column("start", sa.BigInteger(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_interpretation_results_run_id", "interpretation_results", ["run_id"])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
