"""Immutable domain records; byte intervals are always [start, end)."""

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

Offset = Annotated[int, Field(ge=0)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ByteRange(Record):
    start: Offset
    end: Offset

    @model_validator(mode="after")
    def ordered(self):
        if self.end <= self.start:
            raise ValueError("byte range must be nonempty: start < end")
        return self


class Capture(Record):
    id: UUID
    project_id: UUID
    sha256: Sha256
    format: Literal["pcap", "pcapng"]
    relative_path: str
    size_bytes: Offset
    checksum_policy: Literal["warn", "ignore", "reject"] = "warn"
    imported_at: datetime

    @model_validator(mode="after")
    def managed_path(self):
        path = PurePosixPath(self.relative_path)
        if (
            not self.relative_path
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in self.relative_path
            or ":" in self.relative_path
        ):
            raise ValueError("capture path must be a relative project path")
        return self


class Packet(Record):
    id: UUID
    capture_id: UUID
    index: Offset
    timestamp_ns: int
    file_offset: Offset
    captured_length: Offset
    original_length: Offset
    payload_offset: Offset | None = None
    payload_length: Offset = 0
    diagnostics: tuple[str, ...] = ()


class Endpoint(Record):
    address: IPvAnyAddress
    port: Annotated[int, Field(ge=0, le=65535)]

    @model_validator(mode="after")
    def ipv4_only(self):
        if self.address.version != 4:
            raise ValueError("only IPv4 is supported")
        return self


class Session(Record):
    id: UUID  # Concrete connection instance, never a four-tuple identity.
    capture_id: UUID
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    first_packet_id: UUID
    start_known: bool
    roles_known: bool
    diagnostics: tuple[str, ...] = ()


class StreamRange(Record):
    stream_id: UUID
    reconstruction_version: str
    byte_range: ByteRange


class SourceRange(Record):
    capture_id: UUID
    packet_id: UUID
    packet_payload_range: ByteRange  # Relative to TCP payload, not packet start.
    stream: StreamRange

    @model_validator(mode="after")
    def same_length(self):
        if (
            self.packet_payload_range.end - self.packet_payload_range.start
            != self.stream.byte_range.end - self.stream.byte_range.start
        ):
            raise ValueError("source and stream ranges must have equal lengths")
        return self


class StreamIssue(Record):
    byte_range: ByteRange
    status: Literal["gap", "truncated", "ambiguous"]
    diagnostic: str


class DirectedStream(Record):
    id: UUID
    session_id: UUID
    direction: Literal["a_to_b", "b_to_a"]
    reconstruction_version: str
    reconstruction_policy: str
    extent: Offset  # Sequence extent, including missing bytes; not stored-byte count.
    issues: tuple[StreamIssue, ...] = ()


class Message(Record):
    id: UUID
    stream: StreamRange
    framing_version: str
    boundary_status: Literal["known", "uncertain"]
    sources: tuple[SourceRange, ...]


class InterpretationVersion(Record):
    id: UUID
    model_id: UUID
    schema_version: str
    content_sha256: Sha256
    document_json: str  # Immutable serialized JSON, validated against the interpretation schema.
    created_at: datetime
    parent_id: UUID | None = None


class Observation(Record):
    id: UUID
    project_id: UUID
    text: str
    anchors: tuple[StreamRange, ...]
    sources: tuple[SourceRange, ...]


class Hypothesis(Record):
    id: UUID
    project_id: UUID
    statement: str
    rationale: str
    scope: str
    observation_ids: tuple[UUID, ...]
    unknowns: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()


class Corpus(Record):
    id: UUID
    capture_ids: tuple[UUID, ...]
    selection_json: str  # Explicit persisted filters, not current UI selection.


class ValidationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    NOT_APPLICABLE = "not_applicable"


class CaptureIdentity(Record):
    id: UUID
    sha256: Sha256


class ValidationRun(Record):
    id: UUID
    corpus: Corpus
    sources: tuple[CaptureIdentity, ...]
    interpretation_version_id: UUID
    reconstruction_settings_json: str
    framing_settings_json: str
    engine_version: str
    created_at: datetime
    result_relative_path: str | None = None
