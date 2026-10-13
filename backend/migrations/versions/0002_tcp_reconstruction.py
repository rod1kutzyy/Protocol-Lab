"""Add immutable reconstruction, TCP evidence and source-anchored observations."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002_tcp_reconstruction"
down_revision = "0001_capture_storage"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "reconstructions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("capture_id", sa.Uuid(), sa.ForeignKey("captures.id"), nullable=False),
        sa.Column("version", sa.String(30), nullable=False),
        sa.Column("relative_path", sa.String(150), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
        sa.UniqueConstraint("capture_id", "version", name="uq_reconstruction_version"),
    )
    op.create_index("ix_reconstructions_capture_id", "reconstructions", ["capture_id"])
    op.create_table(
        "tcp_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "reconstruction_id", sa.Uuid(), sa.ForeignKey("reconstructions.id"), nullable=False
        ),
        sa.Column("capture_id", sa.Uuid(), sa.ForeignKey("captures.id"), nullable=False),
        sa.Column("first_index", sa.Integer(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_tcp_sessions_reconstruction_id", "tcp_sessions", ["reconstruction_id"])
    op.create_index("ix_tcp_sessions_capture_id", "tcp_sessions", ["capture_id"])
    op.create_table(
        "tcp_streams",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey("tcp_sessions.id"), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_tcp_streams_session_id", "tcp_streams", ["session_id"])
    op.create_table(
        "tcp_spans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("stream_id", sa.Uuid(), sa.ForeignKey("tcp_streams.id"), nullable=False),
        sa.Column("start", sa.BigInteger(), nullable=False),
        sa.Column("end", sa.BigInteger(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
        sa.UniqueConstraint("stream_id", "start", name="uq_stream_span_start"),
    )
    op.create_index("ix_tcp_spans_stream_id", "tcp_spans", ["stream_id"])
    op.create_table(
        "observations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_observations_project_id", "observations", ["project_id"])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
