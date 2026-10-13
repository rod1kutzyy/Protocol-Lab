"""Immutable framing publication and paginated range metadata."""

import os
from pathlib import Path
from uuid import uuid5

from sqlalchemy import insert, select, text
from sqlalchemy.orm import Session

from protocol_lab.capture.index import sha256_file
from protocol_lab.framing.engine import VERSION, FramingResult, Piece, identity
from protocol_lab.framing.source import stream_input
from protocol_lab.storage.database import FramingPieceRow, FramingRunRow
from protocol_lab.storage.projects import StorageError
from protocol_lab.storage.reconstruction import ReconstructionStore


class RunView(FramingResult):
    pieces: tuple[Piece, ...] = ()


class FramingStore:
    def __init__(self, projects):
        self.projects, self.engine = projects, projects.engine
        self.tcp = ReconstructionStore(projects)

    def context(self, stream_id):
        stream = self.tcp.stream(stream_id)
        session = self.tcp.session(stream.session_id)
        capture = self.projects.get_capture(session.capture_id)
        return stream, capture

    def input(self, stream, source):
        return stream_input(stream, self.tcp.spans(stream.id), source)

    def publish(self, stream_id, spec, artifact: Path, summary):
        stream, capture = self.context(stream_id)
        self.projects.verify_source(capture.id)
        result = FramingResult.model_validate_json(artifact.read_text())
        expected = identity(stream_id, stream.reconstruction_version, capture.sha256, spec)
        if (
            result.id != expected
            or result.stream_id != stream_id
            or result.capture_id != capture.id
            or result.capture_sha256 != capture.sha256
            or result.spec != spec
            or result.engine_version != VERSION
            or result.extent != stream.extent
            or result.reconstruction_version != stream.reconstruction_version
        ):
            raise StorageError("Framing source/settings/version mismatch; no result published")
        cursor = 0
        for p in result.pieces:
            if (
                p.framing_version != str(result.id)
                or p.anchor.stream_id != stream_id
                or p.anchor.reconstruction_version != stream.reconstruction_version
                or p.anchor.byte_range.start != cursor
                or p.anchor.byte_range.end <= cursor
                or p.id != uuid5(result.id, f"{p.kind}:{cursor}:{p.anchor.byte_range.end}")
            ):
                raise StorageError("Framing coverage/provenance mismatch")
            cursor = p.anchor.byte_range.end
        if cursor != stream.extent:
            raise StorageError("Framing result does not account for entire stream")
        if (
            len(result.pieces) > spec.max_pieces
            or result.message_count != sum(p.kind == "message" for p in result.pieces)
            or result.leftover_bytes
            != sum(
                p.anchor.byte_range.end - p.anchor.byte_range.start
                for p in result.pieces
                if p.kind == "leftover"
            )
            or result.uncertain_bytes
            != sum(
                p.anchor.byte_range.end - p.anchor.byte_range.start
                for p in result.pieces
                if p.data_status != "known"
            )
        ):
            raise StorageError("Framing coverage summary mismatch")
        checksum = sha256_file(artifact)
        relative = f"derived/framing-{result.id}-{checksum}.json"
        destination = self.projects.safe_path(capture.project_id, relative)
        with Session(self.engine) as db, db.begin():
            key = int.from_bytes(result.id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            old = db.get(FramingRunRow, result.id)
            if old:
                path = self.projects.safe_path(capture.project_id, old.relative_path)
                if not path.exists() or sha256_file(path) != old.sha256 or old.sha256 != checksum:
                    raise StorageError("Stored immutable framing checksum mismatch")
                return {"outcome": "already_framed", "run_id": str(result.id), **summary}
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise StorageError("Framing artifact exists with different checksum")
            else:
                os.link(artifact, destination)
                destination.chmod(0o444)
            db.add(
                FramingRunRow(
                    id=result.id,
                    stream_id=stream_id,
                    project_id=capture.project_id,
                    relative_path=relative,
                    sha256=checksum,
                    metadata_json=result.model_dump(mode="json", exclude={"pieces"}),
                )
            )
            db.flush()
            batch = []
            for piece in result.pieces:
                batch.append(
                    dict(
                        id=piece.id,
                        run_id=result.id,
                        start=piece.anchor.byte_range.start,
                        metadata_json=piece.model_dump(mode="json"),
                    )
                )
                if len(batch) == 1000:
                    db.execute(insert(FramingPieceRow), batch)
                    batch = []
            if batch:
                db.execute(insert(FramingPieceRow), batch)
        return {"outcome": "framed", "run_id": str(result.id), **summary}

    def runs(self, stream_id, offset, limit):
        self.context(stream_id)
        with Session(self.engine) as db:
            return [
                RunView.model_validate(row)
                for row in db.scalars(
                    select(FramingRunRow.metadata_json)
                    .where(FramingRunRow.stream_id == stream_id)
                    .order_by(FramingRunRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def get(self, run_id):
        with Session(self.engine) as db:
            row = db.get(FramingRunRow, run_id)
            if row is None:
                raise KeyError(run_id)
            result = RunView.model_validate(row.metadata_json)
        self.context(result.stream_id)
        return result

    def pieces(self, run_id, offset, limit):
        self.get(run_id)
        with Session(self.engine) as db:
            return [
                Piece.model_validate(row)
                for row in db.scalars(
                    select(FramingPieceRow.metadata_json)
                    .where(FramingPieceRow.run_id == run_id)
                    .order_by(FramingPieceRow.start)
                    .offset(offset)
                    .limit(limit)
                )
            ]
