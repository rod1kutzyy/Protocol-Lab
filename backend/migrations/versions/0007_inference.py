"""Additive A1 inference runs, candidates, evaluations and paginated artifact indexes."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007_inference"
down_revision = "0006_validation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "inference_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column(
            "corpus_version_id", sa.Uuid(), sa.ForeignKey("corpus_versions.id"), nullable=False
        ),
        sa.Column("parent_id", sa.Uuid(), sa.ForeignKey("inference_runs.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_table(
        "inference_candidates",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("inference_runs.id"), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("family", sa.String(30), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_table(
        "inference_evaluations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "candidate_id", sa.Uuid(), sa.ForeignKey("inference_candidates.id"), nullable=False
        ),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column(
            "corpus_version_id", sa.Uuid(), sa.ForeignKey("corpus_versions.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_table(
        "inference_evidence",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("inference_runs.id"), nullable=False),
        sa.Column(
            "candidate_id", sa.Uuid(), sa.ForeignKey("inference_candidates.id"), nullable=False
        ),
        sa.Column("evaluation_id", sa.Uuid(), sa.ForeignKey("inference_evaluations.id")),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("file_offset", sa.BigInteger(), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
    )
    for table, columns in {
        "inference_runs": ["project_id"],
        "inference_candidates": ["run_id", "family"],
        "inference_evaluations": ["candidate_id", "project_id"],
        "inference_evidence": ["run_id", "candidate_id", "evaluation_id", "status"],
    }.items():
        for column in columns:
            op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
