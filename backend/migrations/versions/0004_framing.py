"""Immutable framing runs and pieces; original evidence remains unchanged."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004_framing"
down_revision = "0003_investigation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "framing_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("stream_id", sa.Uuid(), sa.ForeignKey("tcp_streams.id"), nullable=False),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_framing_runs_stream_id", "framing_runs", ["stream_id"])
    op.create_index("ix_framing_runs_project_id", "framing_runs", ["project_id"])
    op.create_table(
        "framing_pieces",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("framing_runs.id"), nullable=False),
        sa.Column("start", sa.BigInteger(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_framing_pieces_run_id", "framing_pieces", ["run_id"])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
