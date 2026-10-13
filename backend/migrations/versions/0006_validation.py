"""Versioned research hypotheses, corpus scope and reproducible validation."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006_validation"
down_revision = "0005_interpretations"
branch_labels = None
depends_on = None


def upgrade():
    for table, identity in [
        ("hypothesis_versions", "hypothesis_id"),
        ("corpus_versions", "corpus_id"),
    ]:
        op.create_table(
            table,
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(identity, sa.Uuid(), nullable=False),
            sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("parent_id", sa.Uuid(), sa.ForeignKey(f"{table}.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("metadata_json", JSONB(), nullable=False),
        )
        for column in [identity, "project_id"]:
            op.create_index(f"ix_{table}_{column}", table, [column])
    op.create_table(
        "validation_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column(
            "corpus_version_id", sa.Uuid(), sa.ForeignKey("corpus_versions.id"), nullable=False
        ),
        sa.Column(
            "interpretation_version_id",
            sa.Uuid(),
            sa.ForeignKey("interpretation_versions.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    for column in ["project_id", "corpus_version_id", "interpretation_version_id"]:
        op.create_index(f"ix_validation_runs_{column}", "validation_runs", [column])
    op.create_table(
        "validation_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("validation_runs.id"), nullable=False),
        sa.Column("capture_id", sa.Uuid(), sa.ForeignKey("captures.id"), nullable=False),
        sa.Column("stream_id", sa.Uuid(), sa.ForeignKey("tcp_streams.id")),
        sa.Column("start", sa.BigInteger(), nullable=False),
        sa.Column("end", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("values_sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    for column in ["run_id", "status"]:
        op.create_index(f"ix_validation_results_{column}", "validation_results", [column])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
