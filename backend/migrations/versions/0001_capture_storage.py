"""Create project, capture and packet metadata; additive initial schema."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_capture_storage"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("directory", sa.String(40), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "captures",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("relative_path", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("checksum_policy", sa.String(10), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=False),
        sa.Column("diagnostics", postgresql.JSONB(), nullable=False),
        sa.Column("import_settings", postgresql.JSONB(), nullable=False),
        sa.Column("engine_version", sa.String(30), nullable=False),
        sa.UniqueConstraint("project_id", "sha256", name="uq_capture_project_hash"),
    )
    op.create_index("ix_captures_project_id", "captures", ["project_id"])
    op.create_table(
        "packets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("capture_id", sa.Uuid(), sa.ForeignKey("captures.id"), nullable=False),
        sa.Column("index", sa.Integer(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("capture_id", "index", name="uq_packet_capture_index"),
    )
    op.create_index("ix_packets_capture_id", "packets", ["capture_id"])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
