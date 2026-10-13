"""Action-log research and exact session times; existing sources remain unchanged."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003_investigation"
down_revision = "0002_tcp_reconstruction"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tcp_sessions", sa.Column("start_ns", sa.Numeric(30, 0), nullable=True))
    op.add_column("tcp_sessions", sa.Column("end_ns", sa.Numeric(30, 0), nullable=True))
    op.execute("""UPDATE tcp_sessions s SET start_ns=t.first_ns, end_ns=t.last_ns FROM (
        SELECT s2.id, min((p.metadata_json->>'timestamp_ns')::numeric) AS first_ns,
               max((p.metadata_json->>'timestamp_ns')::numeric) AS last_ns
        FROM tcp_sessions s2
        CROSS JOIN LATERAL jsonb_array_elements_text(s2.metadata_json->'packet_ids') AS ids(id)
        JOIN packets p ON p.id=ids.id::uuid GROUP BY s2.id
        ) t WHERE s.id=t.id""")
    op.create_table(
        "action_logs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("clock_offset_ns", sa.Numeric(30, 0), nullable=False),
        sa.Column("clock_revision", sa.Integer(), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
        sa.UniqueConstraint("project_id", "sha256", name="uq_log_project_hash"),
    )
    op.create_index("ix_action_logs_project_id", "action_logs", ["project_id"])
    op.create_table(
        "actions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("log_id", sa.Uuid(), sa.ForeignKey("action_logs.id"), nullable=False),
        sa.Column("row_index", sa.Integer(), nullable=False),
        sa.Column("timestamp_ns", sa.Numeric(30, 0), nullable=False),
        sa.Column("metadata_json", JSONB(), nullable=False),
    )
    op.create_index("ix_actions_log_id", "actions", ["log_id"])
    op.create_index("ix_actions_timestamp_ns", "actions", ["timestamp_ns"])
    op.create_table(
        "action_links",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("action_id", sa.Uuid(), sa.ForeignKey("actions.id"), nullable=False),
        sa.Column("observation_id", sa.Uuid(), sa.ForeignKey("observations.id"), nullable=False),
    )
    op.create_index("ix_action_links_project_id", "action_links", ["project_id"])
    op.create_index("ix_action_links_action_id", "action_links", ["action_id"])


def downgrade():
    raise RuntimeError("Destructive downgrade requires explicit authorization; restore a backup")
