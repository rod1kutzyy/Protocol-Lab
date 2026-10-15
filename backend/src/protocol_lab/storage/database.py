"""PostgreSQL metadata. No automatic schema creation or destructive reset."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "projects"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    format_version: Mapped[int] = mapped_column(Integer)
    directory: Mapped[str] = mapped_column(String(40), unique=True)  # relative UUID directory
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaptureRow(Base):
    __tablename__ = "captures"
    __table_args__ = (UniqueConstraint("project_id", "sha256", name="uq_capture_project_hash"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(10))
    relative_path: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    checksum_policy: Mapped[str] = mapped_column(String(10))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    packet_count: Mapped[int] = mapped_column(Integer)
    diagnostics: Mapped[dict] = mapped_column(JSONB)
    import_settings: Mapped[dict] = mapped_column(JSONB)
    engine_version: Mapped[str] = mapped_column(String(30))


class PacketRow(Base):
    __tablename__ = "packets"
    __table_args__ = (UniqueConstraint("capture_id", "index", name="uq_packet_capture_index"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    capture_id: Mapped[UUID] = mapped_column(ForeignKey("captures.id"), index=True)
    index: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[dict] = mapped_column(
        JSONB
    )  # IndexedPacket; no packet payload stored here.


def make_engine(url: str):
    if not url.startswith("postgresql+psycopg://"):
        raise ValueError("PROTOCOL_LAB_DATABASE_URL must use postgresql+psycopg")
    return create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})


class ReconstructionRow(Base):
    __tablename__ = "reconstructions"
    __table_args__ = (UniqueConstraint("capture_id", "version", name="uq_reconstruction_version"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    capture_id: Mapped[UUID] = mapped_column(ForeignKey("captures.id"), index=True)
    version: Mapped[str] = mapped_column(String(30))
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class SessionRow(Base):
    __tablename__ = "tcp_sessions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    reconstruction_id: Mapped[UUID] = mapped_column(ForeignKey("reconstructions.id"), index=True)
    capture_id: Mapped[UUID] = mapped_column(ForeignKey("captures.id"), index=True)
    first_index: Mapped[int] = mapped_column(Integer)
    start_ns: Mapped[int | None] = mapped_column(Numeric(30, 0))
    end_ns: Mapped[int | None] = mapped_column(Numeric(30, 0))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class StreamRow(Base):
    __tablename__ = "tcp_streams"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("tcp_sessions.id"), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class SpanRow(Base):
    __tablename__ = "tcp_spans"
    __table_args__ = (UniqueConstraint("stream_id", "start", name="uq_stream_span_start"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    stream_id: Mapped[UUID] = mapped_column(ForeignKey("tcp_streams.id"), index=True)
    start: Mapped[int] = mapped_column(BigInteger)
    end: Mapped[int] = mapped_column(BigInteger)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ObservationRow(Base):
    __tablename__ = "observations"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ActionLogRow(Base):
    __tablename__ = "action_logs"
    __table_args__ = (UniqueConstraint("project_id", "sha256", name="uq_log_project_hash"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    clock_offset_ns: Mapped[int] = mapped_column(Numeric(30, 0))
    clock_revision: Mapped[int] = mapped_column(Integer)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ActionRow(Base):
    __tablename__ = "actions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    log_id: Mapped[UUID] = mapped_column(ForeignKey("action_logs.id"), index=True)
    row_index: Mapped[int] = mapped_column(Integer)
    timestamp_ns: Mapped[int] = mapped_column(Numeric(30, 0), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ActionLinkRow(Base):
    __tablename__ = "action_links"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    action_id: Mapped[UUID] = mapped_column(ForeignKey("actions.id"), index=True)
    observation_id: Mapped[UUID] = mapped_column(ForeignKey("observations.id"))


class FramingRunRow(Base):
    __tablename__ = "framing_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    stream_id: Mapped[UUID] = mapped_column(ForeignKey("tcp_streams.id"), index=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class FramingPieceRow(Base):
    __tablename__ = "framing_pieces"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("framing_runs.id"), index=True)
    start: Mapped[int] = mapped_column(BigInteger)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InterpretationRow(Base):
    __tablename__ = "interpretation_versions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    model_id: Mapped[UUID] = mapped_column(index=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    parent_id: Mapped[UUID | None] = mapped_column(ForeignKey("interpretation_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InterpretationRunRow(Base):
    __tablename__ = "interpretation_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    framing_run_id: Mapped[UUID] = mapped_column(ForeignKey("framing_runs.id"), index=True)
    version_id: Mapped[UUID] = mapped_column(ForeignKey("interpretation_versions.id"), index=True)
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InterpretationResultRow(Base):
    __tablename__ = "interpretation_results"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("interpretation_runs.id"), index=True)
    start: Mapped[int] = mapped_column(BigInteger)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class HypothesisRow(Base):
    __tablename__ = "hypothesis_versions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    hypothesis_id: Mapped[UUID] = mapped_column(index=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    parent_id: Mapped[UUID | None] = mapped_column(ForeignKey("hypothesis_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class CorpusRow(Base):
    __tablename__ = "corpus_versions"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    corpus_id: Mapped[UUID] = mapped_column(index=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    parent_id: Mapped[UUID | None] = mapped_column(ForeignKey("corpus_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ValidationRunRow(Base):
    __tablename__ = "validation_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    corpus_version_id: Mapped[UUID] = mapped_column(ForeignKey("corpus_versions.id"), index=True)
    interpretation_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("interpretation_versions.id"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class ValidationResultRow(Base):
    __tablename__ = "validation_results"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("validation_runs.id"), index=True)
    capture_id: Mapped[UUID] = mapped_column(ForeignKey("captures.id"))
    stream_id: Mapped[UUID | None] = mapped_column(ForeignKey("tcp_streams.id"))
    start: Mapped[int] = mapped_column(BigInteger)
    end: Mapped[int] = mapped_column(BigInteger)
    kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), index=True)
    values_sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InferenceRunRow(Base):
    __tablename__ = "inference_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    corpus_version_id: Mapped[UUID] = mapped_column(ForeignKey("corpus_versions.id"))
    parent_id: Mapped[UUID | None] = mapped_column(ForeignKey("inference_runs.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InferenceCandidateRow(Base):
    __tablename__ = "inference_candidates"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("inference_runs.id"), index=True)
    rank: Mapped[int] = mapped_column(Integer)
    family: Mapped[str] = mapped_column(String(30), index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InferenceEvaluationRow(Base):
    __tablename__ = "inference_evaluations"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("inference_candidates.id"), index=True)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"), index=True)
    corpus_version_id: Mapped[UUID] = mapped_column(ForeignKey("corpus_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    relative_path: Mapped[str] = mapped_column(String(150))
    sha256: Mapped[str] = mapped_column(String(64))
    metadata_json: Mapped[dict] = mapped_column(JSONB)


class InferenceEvidenceRow(Base):
    __tablename__ = "inference_evidence"
    id: Mapped[UUID] = mapped_column(primary_key=True)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("inference_runs.id"), index=True)
    candidate_id: Mapped[UUID] = mapped_column(ForeignKey("inference_candidates.id"), index=True)
    evaluation_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("inference_evaluations.id"), index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), index=True)
    file_offset: Mapped[int] = mapped_column(BigInteger)
    length: Mapped[int] = mapped_column(Integer)
