"""Explicit corpus scope and immutable inputs/results for reproducible validation."""

from datetime import datetime
from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from protocol_lab.domain.diagnostics import TechnicalLimit
from protocol_lab.domain.models import Record, StreamRange
from protocol_lab.framing.engine import FramingSpec
from protocol_lab.interpretation.engine import DecodedField, UnknownRange
from protocol_lab.research.action_logs import ActionEvent

Status = Literal["passed", "failed", "unknown", "ambiguous", "not_applicable"]
STATUSES = ("passed", "failed", "unknown", "ambiguous", "not_applicable")
VERSION = "validation-v4"


class CorpusSpec(Record):
    capture_ids: tuple[UUID, ...] = Field(min_length=1, max_length=1000)
    direction: Literal["both", "a_to_b", "b_to_a"] = "both"
    address: IPv4Address | None = None
    port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    start_ns: str | None = Field(default=None, pattern=r"^-?\d{1,30}$")
    end_ns: str | None = Field(default=None, pattern=r"^-?\d{1,30}$")

    @field_validator("capture_ids")
    @classmethod
    def ordered(cls, value):
        return tuple(sorted(value, key=str))

    @model_validator(mode="after")
    def unique(self):
        if len(set(self.capture_ids)) != len(self.capture_ids):
            raise ValueError("Duplicate capture IDs in corpus")
        if (
            self.start_ns is not None
            and self.end_ns is not None
            and int(self.start_ns) > int(self.end_ns)
        ):
            raise ValueError("Corpus start is after end")
        return self


class CorpusInput(Record):
    name: str = Field(min_length=1, max_length=200)
    spec: CorpusSpec
    parent_id: UUID | None = None


class StoredCorpus(CorpusInput):
    id: UUID
    corpus_id: UUID
    project_id: UUID
    sha256: str
    created_at: datetime


class StreamSnapshot(Record):
    id: UUID
    session_id: UUID
    reconstruction_version: str
    reconstruction_policy: str
    extent: int
    direction: str
    included: bool
    data_status_bytes: dict[str, int] = Field(default_factory=dict)


class ReconstructionFailure(Record):
    session_id: UUID
    direction: Literal["a_to_b", "b_to_a"]
    included: bool
    diagnostic: str


class CaptureSnapshot(Record):
    id: UUID
    sha256: str
    size_bytes: int
    packet_count: int
    eligible_packets: int
    checksum_policy: str
    import_settings: dict
    import_engine_version: str
    diagnostics: dict
    reconstruction_id: UUID | None
    reconstruction_sha256: str | None
    reconstruction_settings: dict | None
    reconstruction_engine_version: str | None
    streams: tuple[StreamSnapshot, ...]
    reconstruction_failures: tuple[ReconstructionFailure, ...] = ()


class RunInput(Record):
    corpus_version_id: UUID
    interpretation_version_id: UUID
    log_ids: tuple[UUID, ...] = Field(default=(), max_length=128)


class RunSnapshot(Record):
    id: UUID
    project_id: UUID
    created_at: datetime
    corpus: StoredCorpus
    interpretation_version_id: UUID
    model_id: UUID
    model_sha256: str
    document_json: str
    framing: FramingSpec
    framing_engine_version: str
    interpretation_engine_version: str
    engine_version: str = VERSION
    sources: tuple[CaptureSnapshot, ...]
    action_events: tuple[ActionEvent, ...] = Field(default=(), max_length=100000)
    action_logs: tuple[dict, ...] = Field(default=(), max_length=128)


class ValidationItem(Record):
    id: UUID
    capture_id: UUID
    session_id: UUID | None = None
    direction: Literal["a_to_b", "b_to_a"] | None = None
    stream_id: UUID | None = None
    anchor: StreamRange | None = None
    framing_version: str | None = None
    kind: Literal[
        "message",
        "leftover",
        "excluded",
        "stream_diagnostic",
        "capture_diagnostic",
        "reconstruction_diagnostic",
        "corpus_check",
    ]
    status: Status
    diagnostic: str
    fields: tuple[DecodedField, ...] = ()
    unknown_ranges: tuple[UnknownRange, ...] = ()
    technical_limit: TechnicalLimit | None = None
    check_name: str | None = None
    check_ordinal: int = Field(default=0, ge=0)
    related_anchors: tuple[StreamRange, ...] = Field(default=(), max_length=16)


class Coverage(Record):
    counts: dict[str, int]
    message_counts: dict[str, int]
    byte_counts: dict[str, int]
    stream_bytes: int
    selected_stream_bytes: int
    excluded_stream_bytes: int
    unframed_bytes: int
    undecoded_bytes: int
    decoded_leaf_bytes: int
    captures: int
    captures_without_reconstruction: int
    packets: int
    noneligible_packets: int
    unavailable_source_bytes: int
    ambiguous_source_bytes: int
    unreconstructed_directions: int = 0
    excluded_unreconstructed_directions: int = 0
    corpus_check_counts: dict[str, int] = Field(default_factory=dict)


class ValidationRun(Record):
    snapshot: RunSnapshot
    coverage: Coverage


class ValidationRunSummary(Record):
    id: UUID
    project_id: UUID
    created_at: datetime
    corpus_version_id: UUID
    corpus_id: UUID
    corpus_name: str
    interpretation_version_id: UUID
    model_id: UUID
    coverage: Coverage


class ValidationSummary(Record):
    id: UUID
    capture_id: UUID
    session_id: UUID | None
    direction: Literal["a_to_b", "b_to_a"] | None = None
    stream_id: UUID | None
    anchor: StreamRange | None
    framing_version: str | None
    kind: str
    status: Status
    diagnostic: str
    field_count: int
    unknown_range_count: int
    values_sha256: str
    technical_limit: TechnicalLimit | None = None
    check_name: str | None = None
    check_ordinal: int = 0
    related_anchors: tuple[StreamRange, ...] = ()


class Currentness(Record):
    checked_at: datetime
    details: tuple[str, ...] = ()
    stale: bool
    reasons: tuple[str, ...]
    latest_model_version_id: UUID
    latest_corpus_version_id: UUID


class Difference(Record):
    left: ValidationSummary | None
    right: ValidationSummary | None
    change: Literal["added", "removed", "status", "values", "diagnostic"]


class Comparison(Record):
    left_run_id: UUID
    right_run_id: UUID
    same_sources: bool
    counts: dict[str, int]
    items: list[Difference]
    next_offset: int | None
