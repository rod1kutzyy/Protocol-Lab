"""Transactional publication and bounded reads of immutable TCP evidence."""

import os
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from pydantic import Field
from sqlalchemy import Numeric, cast, insert, or_, select, text
from sqlalchemy.orm import Session

from protocol_lab.capture.index import IndexedPacket, sha256_file
from protocol_lab.domain.models import ByteRange, Observation, Record, StreamRange
from protocol_lab.domain.models import Session as TCPSession
from protocol_lab.storage.database import (
    CaptureRow,
    ObservationRow,
    PacketRow,
    ReconstructionRow,
    SessionRow,
    SpanRow,
    StreamRow,
)
from protocol_lab.storage.projects import ProjectStore, StorageError
from protocol_lab.tcp.reassembly import (
    VERSION,
    Evidence,
    RebuiltSession,
    RebuiltStream,
    Reconstruction,
    Span,
)


class SessionView(TCPSession):
    section_index: int
    interface_id: int
    packet_count: int
    closed: bool
    streams: tuple[RebuiltStream, ...]
    start_timestamp_ns: str | None = None
    end_timestamp_ns: str | None = None

    @classmethod
    def from_session(cls, session, start=None, end=None):
        return cls(
            **session.model_dump(exclude={"packet_ids"}),
            packet_count=len(session.packet_ids),
            start_timestamp_ns=str(int(start)) if start is not None else None,
            end_timestamp_ns=str(int(end)) if end is not None else None,
        )


class ByteVariant(Record):
    data_hex: str
    sources: tuple[Evidence, ...]


class RangeBlock(Record):
    byte_range: ByteRange
    status: str
    variants: tuple[ByteVariant, ...]


class StreamBytes(Record):
    stream_id: UUID
    reconstruction_version: str
    offset: int
    length: int
    extent: int
    blocks: tuple[RangeBlock, ...]


class ObservationInput(Record):
    text: str = Field(min_length=1, max_length=10000)
    anchors: tuple[StreamRange, ...] = Field(min_length=1, max_length=16)


class ReconstructionStore:
    def __init__(self, projects: ProjectStore):
        self.projects = projects
        self.engine = projects.engine

    def packet_records(self, capture_id):
        with Session(self.engine) as db:
            for metadata in db.scalars(
                select(PacketRow.metadata_json)
                .where(PacketRow.capture_id == capture_id)
                .order_by(PacketRow.index)
                .execution_options(yield_per=1000)
            ):
                yield IndexedPacket.model_validate(metadata)

    def publish(self, capture_id: UUID, artifact: Path, summary: dict) -> dict:
        capture = self.projects.get_capture(capture_id)
        self.projects.get(capture.project_id)
        self.projects.verify_source(capture_id)
        result = Reconstruction.model_validate_json(artifact.read_text())
        if result.capture_id != capture_id or result.version != VERSION:
            raise StorageError("Reconstruction source/version mismatch; no result published")
        checksum = sha256_file(artifact)
        reconstruction_id = uuid5(capture_id, VERSION)
        relative = f"derived/{reconstruction_id}-{checksum}.json"
        destination = self.projects.safe_path(capture.project_id, relative)
        with Session(self.engine) as db, db.begin():
            key = int.from_bytes(capture_id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            old = db.get(ReconstructionRow, reconstruction_id)
            if old:
                stored = self.projects.safe_path(capture.project_id, old.relative_path)
                if not stored.exists() or sha256_file(stored) != old.sha256:
                    raise StorageError("Stored reconstruction checksum mismatch")
                if old.sha256 != checksum:
                    raise StorageError("Immutable reconstruction differs; use a new engine version")
                return {
                    "outcome": "already_reconstructed",
                    "capture_id": str(capture_id),
                    "reconstruction_id": str(reconstruction_id),
                    **summary,
                }
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise StorageError("Derived destination checksum mismatch; refusing overwrite")
            else:
                os.link(artifact, destination)
                destination.chmod(0o444)
            db.add(
                ReconstructionRow(
                    id=reconstruction_id,
                    capture_id=capture_id,
                    version=VERSION,
                    relative_path=relative,
                    sha256=checksum,
                    metadata_json=result.model_dump(mode="json", exclude={"sessions"}),
                )
            )
            db.flush()
            for index, session in enumerate(result.sessions):
                metadata = session.model_dump(mode="json")
                metadata["streams"] = [
                    s.model_dump(mode="json", exclude={"spans"}) for s in session.streams
                ]
                first_ns, last_ns = self.packet_times(db, session.packet_ids)
                db.add(
                    SessionRow(
                        id=session.id,
                        capture_id=capture_id,
                        reconstruction_id=reconstruction_id,
                        first_index=index,
                        start_ns=first_ns,
                        end_ns=last_ns,
                        metadata_json=metadata,
                    )
                )
                db.flush()
                for stream in session.streams:
                    db.add(
                        StreamRow(
                            id=stream.id,
                            session_id=session.id,
                            metadata_json=stream.model_dump(mode="json", exclude={"spans"}),
                        )
                    )
                    db.flush()
                    batch = []
                    for span in stream.spans:
                        batch.append(
                            dict(
                                id=uuid5(stream.id, str(span.byte_range.start)),
                                stream_id=stream.id,
                                start=span.byte_range.start,
                                end=span.byte_range.end,
                                metadata_json=span.model_dump(mode="json"),
                            )
                        )
                        if len(batch) == 1000:
                            db.execute(insert(SpanRow), batch)
                            batch = []
                    if batch:
                        db.execute(insert(SpanRow), batch)
        return {
            "outcome": "reconstructed",
            "capture_id": str(capture_id),
            "reconstruction_id": str(reconstruction_id),
            **summary,
        }

    def sessions(self, capture_id, offset, limit):
        capture = self.projects.get_capture(capture_id)
        self.projects.get(capture.project_id)
        with Session(self.engine) as db:
            if db.get(ReconstructionRow, uuid5(capture_id, VERSION)) is None:
                raise StorageError("Capture has no completed reconstruction; start reconstruction")
            return [
                SessionView.from_session(
                    RebuiltSession.model_validate(row.metadata_json), row.start_ns, row.end_ns
                )
                for row in db.scalars(
                    select(SessionRow)
                    .where(SessionRow.capture_id == capture_id)
                    .order_by(SessionRow.first_index)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def session(self, session_id):
        with Session(self.engine) as db:
            row = db.get(SessionRow, session_id)
            if row is None:
                raise KeyError(session_id)
            result = RebuiltSession.model_validate(row.metadata_json)
        capture = self.projects.get_capture(result.capture_id)
        self.projects.get(capture.project_id)
        return result

    def stream(self, stream_id):
        with Session(self.engine) as db:
            row = db.get(StreamRow, stream_id)
            if row is None:
                raise KeyError(stream_id)
            stream = RebuiltStream.model_validate(row.metadata_json)
        self.session(stream.session_id)
        return stream

    def ranges(self, stream_id, offset, length) -> StreamBytes:
        stream = self.stream(stream_id)
        if offset < 0 or length < 1 or length > 65536 or offset + length > stream.extent:
            raise ValueError("Requested range must be within stream extent, length 1..65536")
        session = self.session(stream.session_id)
        capture = self.projects.get_capture(session.capture_id)
        self.projects.verify_source(capture.id)
        source = self.projects.safe_path(capture.project_id, capture.relative_path)
        blocks = []
        read_bytes = 0
        evidence_count = 0
        with Session(self.engine) as db, source.open("rb") as file:
            rows = db.scalars(
                select(SpanRow.metadata_json)
                .where(
                    SpanRow.stream_id == stream_id,
                    SpanRow.start < offset + length,
                    SpanRow.end > offset,
                )
                .order_by(SpanRow.start)
            )
            for metadata in rows:
                span = Span.model_validate(metadata)
                left = max(offset, span.byte_range.start)
                right = min(offset + length, span.byte_range.end)
                interval = ByteRange(start=left, end=right)
                variants = {}
                for evidence in span.sources:
                    evidence_count += 1
                    read_bytes += right - left
                    if evidence_count > 10000 or read_bytes > 4 * 1024 * 1024:
                        raise ValueError(
                            "Range evidence exceeds response limits; request smaller range"
                        )
                    shift = left - span.byte_range.start
                    clipped = evidence.model_copy(
                        update=dict(
                            packet_payload_range=ByteRange(
                                start=evidence.packet_payload_range.start + shift,
                                end=evidence.packet_payload_range.start + shift + right - left,
                            ),
                            stream=evidence.stream.model_copy(update={"byte_range": interval}),
                            file_offset=evidence.file_offset + shift,
                            packet_offset=evidence.packet_offset + shift,
                        )
                    )
                    file.seek(clipped.file_offset)
                    data = file.read(right - left)
                    if len(data) != right - left:
                        raise StorageError(
                            "Source byte range unavailable; remaining index retained"
                        )
                    variants.setdefault(data.hex(), []).append(clipped)
                if (span.status == "known" and len(variants) != 1) or (
                    span.status == "ambiguous" and len(variants) < 2
                ):
                    raise StorageError("Source bytes disagree with reconstruction; verify capture")
                blocks.append(
                    RangeBlock(
                        byte_range=interval,
                        status=span.status,
                        variants=tuple(
                            ByteVariant(data_hex=data, sources=tuple(sources))
                            for data, sources in variants.items()
                        ),
                    )
                )
        return StreamBytes(
            stream_id=stream_id,
            reconstruction_version=VERSION,
            offset=offset,
            length=length,
            extent=stream.extent,
            blocks=tuple(blocks),
        )

    def build_observation(self, project_id: UUID, body: ObservationInput):
        self.projects.get(project_id)
        sources = []
        for anchor in body.anchors:
            stream = self.stream(anchor.stream_id)
            session = self.session(stream.session_id)
            capture = self.projects.get_capture(session.capture_id)
            if capture.project_id != project_id or anchor.reconstruction_version != VERSION:
                raise ValueError("Observation anchor belongs to another project or version")
            data = self.ranges(
                anchor.stream_id,
                anchor.byte_range.start,
                anchor.byte_range.end - anchor.byte_range.start,
            )
            sources.extend(
                source
                for block in data.blocks
                for variant in block.variants
                for source in variant.sources
            )
        observation = Observation(
            id=uuid4(),
            project_id=project_id,
            text=body.text,
            anchors=body.anchors,
            sources=tuple(
                # Domain SourceRange intentionally excludes absolute file offsets.
                source.model_dump(exclude={"file_offset", "packet_offset", "packet_index"})
                for source in sources
            ),
        )
        return observation

    def observe(self, project_id: UUID, body: ObservationInput):
        observation = self.build_observation(project_id, body)
        with Session(self.engine) as db, db.begin():
            db.add(
                ObservationRow(
                    id=observation.id,
                    project_id=project_id,
                    metadata_json=observation.model_dump(mode="json"),
                )
            )
        return observation

    def observations(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            return [
                Observation.model_validate(value)
                for value in db.scalars(
                    select(ObservationRow.metadata_json)
                    .where(ObservationRow.project_id == project_id)
                    .order_by(ObservationRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    @staticmethod
    def packet_times(db, packet_ids):
        first = last = None
        ids = list(packet_ids)
        for offset in range(0, len(ids), 1000):
            times = list(
                db.scalars(
                    select(PacketRow.metadata_json["timestamp_ns"].astext).where(
                        PacketRow.id.in_(ids[offset : offset + 1000])
                    )
                )
            )
            times = [int(value) for value in times if value is not None]
            if times:
                first = min(min(times), first) if first is not None else min(times)
                last = max(max(times), last) if last is not None else max(times)
        return first, last

    def view(self, session_id):
        session = self.session(session_id)
        with Session(self.engine) as db:
            row = db.get(SessionRow, session_id)
            return SessionView.from_session(session, row.start_ns, row.end_ns)

    def project_sessions(
        self,
        project_id,
        offset,
        limit,
        capture_id=None,
        address=None,
        port=None,
        start_ns=None,
        end_ns=None,
    ):
        self.projects.get(project_id)
        if start_ns is not None and end_ns is not None and int(start_ns) > int(end_ns):
            raise ValueError("Start time is after end time")
        query = select(SessionRow).join(CaptureRow).where(CaptureRow.project_id == project_id)
        if capture_id:
            capture = self.projects.get_capture(capture_id)
            if capture.project_id != project_id:
                raise ValueError("Capture belongs to another project")
            query = query.where(SessionRow.capture_id == capture_id)
        metadata = SessionRow.metadata_json
        if address:
            query = query.where(
                or_(
                    metadata["endpoint_a"]["address"].astext == address,
                    metadata["endpoint_b"]["address"].astext == address,
                )
            )
        if port is not None:
            query = query.where(
                or_(
                    cast(metadata["endpoint_a"]["port"].astext, Numeric) == port,
                    cast(metadata["endpoint_b"]["port"].astext, Numeric) == port,
                )
            )
        if start_ns is not None:
            query = query.where(SessionRow.end_ns >= int(start_ns))
        if end_ns is not None:
            query = query.where(SessionRow.start_ns <= int(end_ns))
        with Session(self.engine) as db:
            return [
                SessionView.from_session(
                    RebuiltSession.model_validate(row.metadata_json), row.start_ns, row.end_ns
                )
                for row in db.scalars(
                    query.order_by(SessionRow.capture_id, SessionRow.first_index)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def spans(self, stream_id):
        with Session(self.engine) as db:
            for metadata in db.scalars(
                select(SpanRow.metadata_json)
                .where(SpanRow.stream_id == stream_id)
                .order_by(SpanRow.start)
                .execution_options(yield_per=1000)
            ):
                yield Span.model_validate(metadata)
