"""Immutable JSON model versions and streaming publication of decoded message results."""

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4, uuid5

from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import Session

from protocol_lab.capture.index import sha256_file
from protocol_lab.domain.diagnostics import TechnicalLimit
from protocol_lab.domain.models import InterpretationVersion, Record, StreamRange
from protocol_lab.framing.engine import Piece
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.engine import VERSION, MessageResult
from protocol_lab.interpretation.schema import canonical, content_hash
from protocol_lab.storage.database import (
    FramingPieceRow,
    InterpretationResultRow,
    InterpretationRow,
    InterpretationRunRow,
)
from protocol_lab.storage.framing import FramingStore
from protocol_lab.storage.projects import StorageError


class StoredInterpretation(InterpretationVersion):
    project_id: UUID


class MessageSummary(Record):
    piece_id: str
    anchor: StreamRange
    status: Literal["passed", "failed", "unknown", "ambiguous", "not_applicable"]
    diagnostic: str
    field_count: int
    unknown_range_count: int
    technical_limit: TechnicalLimit | None = None


class DecodeRun(Record):
    id: UUID
    framing_run_id: UUID
    version_id: UUID
    content_sha256: str
    capture_id: UUID
    capture_sha256: str
    reconstruction_version: str
    engine_version: str = VERSION
    piece_count: int
    counts: dict[str, int]


def run_identity(framing_id, version_id):
    return uuid5(framing_id, f"{VERSION}:{version_id}")


class InterpretationStore:
    def __init__(self, projects):
        self.projects, self.engine = projects, projects.engine
        self.framing = FramingStore(projects)

    def save(self, project_id, model, parent_id=None):
        self.projects.get(project_id)
        model_id = uuid4()
        if parent_id:
            parent = self.version(parent_id)
            if parent.project_id != project_id:
                raise ValueError("Interpretation parent belongs to another project")
            model_id = parent.model_id
        checksum = content_hash(model)
        version_id = uuid5(model_id, checksum)
        with Session(self.engine) as db, db.begin():
            key = int.from_bytes(version_id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            old = db.get(InterpretationRow, version_id)
            if old:
                return StoredInterpretation.model_validate(old.metadata_json)
            version = StoredInterpretation(
                id=version_id,
                model_id=model_id,
                project_id=project_id,
                schema_version=model.schema_version,
                content_sha256=checksum,
                document_json=canonical(model),
                created_at=datetime.now(UTC),
                parent_id=parent_id,
            )
            db.add(
                InterpretationRow(
                    id=version_id,
                    model_id=model_id,
                    project_id=project_id,
                    parent_id=parent_id,
                    created_at=version.created_at,
                    metadata_json=version.model_dump(mode="json"),
                )
            )
        return version

    def version(self, version_id):
        with Session(self.engine) as db:
            row = db.get(InterpretationRow, version_id)
            if row is None:
                raise KeyError(version_id)
            version = StoredInterpretation.model_validate(row.metadata_json)
        model = load_model(version.document_json)
        if (
            content_hash(model) != version.content_sha256
            or uuid5(version.model_id, version.content_sha256) != version.id
        ):
            raise StorageError("Immutable interpretation checksum mismatch")
        self.projects.get(version.project_id)
        return version

    def versions(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            return [
                StoredInterpretation.model_validate(row)
                for row in db.scalars(
                    select(InterpretationRow.metadata_json)
                    .where(InterpretationRow.project_id == project_id)
                    .order_by(InterpretationRow.created_at.desc(), InterpretationRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def context(self, framing_id, version_id):
        framing = self.framing.get(framing_id)
        stream, capture = self.framing.context(framing.stream_id)
        if (
            framing.capture_id != capture.id
            or framing.capture_sha256 != capture.sha256
            or framing.reconstruction_version != stream.reconstruction_version
            or framing.extent != stream.extent
        ):
            raise StorageError("Framing source identity does not match reconstruction")
        version = self.version(version_id)
        model = load_model(version.document_json)
        if version.project_id != capture.project_id:
            raise ValueError("Interpretation and framing must belong to the same project")
        if model.framing != framing.spec:
            raise ValueError(
                "Model framing settings differ from selected framing result; "
                "rebuild framing with the model settings"
            )
        return framing, stream, capture, version, model

    def publish(self, framing_id, version_id, artifact: Path, summary):
        framing, stream, capture, version, model = self.context(framing_id, version_id)
        self.projects.verify_source(capture.id)
        with artifact.open() as file:
            result = DecodeRun.model_validate_json(file.readline())
        expected = DecodeRun(
            id=run_identity(framing_id, version_id),
            framing_run_id=framing_id,
            version_id=version_id,
            content_sha256=version.content_sha256,
            capture_id=capture.id,
            capture_sha256=capture.sha256,
            reconstruction_version=stream.reconstruction_version,
            piece_count=result.piece_count,
            counts=result.counts,
        )
        if (
            result != expected
            or result.piece_count != sum(result.counts.values())
            or result.piece_count > framing.spec.max_pieces
        ):
            raise StorageError("Interpretation source/settings/version mismatch")
        checksum = sha256_file(artifact)
        relative = f"derived/interpretation-{result.id}-{checksum}.jsonl"
        destination = self.projects.safe_path(capture.project_id, relative)
        with Session(self.engine) as db, db.begin(), Session(self.engine) as sources:
            key = int.from_bytes(result.id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            old = db.get(InterpretationRunRow, result.id)
            if old:
                path = self.projects.safe_path(capture.project_id, old.relative_path)
                if old.sha256 != checksum or not path.exists() or sha256_file(path) != checksum:
                    raise StorageError("Immutable interpretation result checksum mismatch")
                return {"outcome": "already_interpreted", "run_id": str(result.id), **summary}
            db.add(
                InterpretationRunRow(
                    id=result.id,
                    framing_run_id=framing_id,
                    version_id=version_id,
                    relative_path=relative,
                    sha256=checksum,
                    metadata_json=result.model_dump(mode="json"),
                )
            )
            db.flush()
            expected_pieces = iter(
                sources.scalars(
                    select(FramingPieceRow.metadata_json)
                    .where(FramingPieceRow.run_id == framing_id)
                    .order_by(FramingPieceRow.start)
                    .execution_options(yield_per=1000)
                )
            )
            cursor, count, counts, batch = 0, 0, {}, []
            with artifact.open() as file:
                next(file)
                for line in file:
                    item = MessageResult.model_validate_json(line)
                    original = next(expected_pieces, None)
                    if original is None:
                        raise StorageError("Extra interpretation result outside framing")
                    piece = Piece.model_validate(original)
                    if item.piece_id != str(piece.id) or item.anchor != piece.anchor:
                        raise StorageError("Interpretation message does not match framing anchor")
                    interval = item.anchor.byte_range
                    if (
                        item.anchor.stream_id != stream.id
                        or item.anchor.reconstruction_version != stream.reconstruction_version
                        or interval.start != cursor
                        or interval.end > stream.extent
                    ):
                        raise StorageError("Interpretation result range mismatch")
                    for field in item.fields:
                        if field.anchor and (
                            field.anchor.stream_id != stream.id
                            or field.anchor.reconstruction_version != stream.reconstruction_version
                            or field.anchor.byte_range.start < interval.start
                            or field.anchor.byte_range.end > interval.end
                        ):
                            raise StorageError("Decoded field provenance mismatch")
                    for unknown in item.unknown_ranges:
                        if (
                            unknown.anchor.stream_id != stream.id
                            or unknown.anchor.reconstruction_version
                            != stream.reconstruction_version
                            or unknown.anchor.byte_range.start < interval.start
                            or unknown.anchor.byte_range.end > interval.end
                        ):
                            raise StorageError("Unknown range provenance mismatch")
                    cursor = interval.end
                    count += 1
                    counts[item.status] = counts.get(item.status, 0) + 1
                    batch.append(
                        dict(
                            id=uuid5(result.id, item.piece_id),
                            run_id=result.id,
                            start=interval.start,
                            metadata_json=item.model_dump(mode="json"),
                        )
                    )
                    if len(batch) == 100:
                        db.execute(insert(InterpretationResultRow), batch)
                        batch = []
            if (
                next(expected_pieces, None) is not None
                or cursor != stream.extent
                or count != result.piece_count
                or counts != result.counts
            ):
                raise StorageError("Interpretation result does not account for framing ranges")
            if batch:
                db.execute(insert(InterpretationResultRow), batch)
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise StorageError("Interpretation artifact checksum mismatch")
            else:
                os.link(artifact, destination)
                destination.chmod(0o444)
        return {"outcome": "interpreted", "run_id": str(result.id), **summary}

    def runs(self, framing_id, offset, limit):
        self.framing.get(framing_id)
        with Session(self.engine) as db:
            return [
                DecodeRun.model_validate(row)
                for row in db.scalars(
                    select(InterpretationRunRow.metadata_json)
                    .where(InterpretationRunRow.framing_run_id == framing_id)
                    .order_by(InterpretationRunRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def get(self, run_id):
        with Session(self.engine) as db:
            row = db.get(InterpretationRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            result = DecodeRun.model_validate(row.metadata_json)
        self.context(result.framing_run_id, result.version_id)
        return result

    def results(self, run_id, offset, limit):
        self.get(run_id)
        with Session(self.engine) as db:
            metadata = InterpretationResultRow.metadata_json
            query = (
                select(
                    metadata.op("-")("fields").op("-")("unknown_ranges"),
                    func.jsonb_array_length(metadata["fields"]),
                    func.jsonb_array_length(metadata["unknown_ranges"]),
                )
                .where(InterpretationResultRow.run_id == run_id)
                .order_by(InterpretationResultRow.start)
                .offset(offset)
                .limit(limit)
            )
            return [
                MessageSummary.model_validate(
                    {**row, "field_count": fields, "unknown_range_count": unknown}
                )
                for row, fields, unknown in db.execute(query)
            ]

    def result(self, run_id, piece_id):
        self.get(run_id)
        with Session(self.engine) as db:
            row = db.get(InterpretationResultRow, uuid5(run_id, str(piece_id)))
            if row is None:
                raise KeyError(piece_id)
            return MessageResult.model_validate(row.metadata_json)
