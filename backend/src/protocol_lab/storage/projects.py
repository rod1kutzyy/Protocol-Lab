"""Project directory contract and transactional PostgreSQL repository."""

import os
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import Field
from sqlalchemy import insert, select, text
from sqlalchemy.orm import Session

from protocol_lab import __version__
from protocol_lab.capture.index import CaptureError, IndexedPacket, IndexSettings, sha256_file
from protocol_lab.domain.models import Capture, Record
from protocol_lab.storage.database import CaptureRow, PacketRow, ProjectRow

FORMAT_VERSION = 1
SCHEMA_REVISION = "0001_capture_storage"


class StorageError(ValueError):
    pass


class Project(Record):
    id: UUID
    name: str = Field(min_length=1, max_length=200)
    format_version: int = FORMAT_VERSION
    created_at: datetime


class ProjectManifest(Record):
    format: str = "protocol-lab-project"
    format_version: int = FORMAT_VERSION
    project_id: UUID
    metadata_schema_revision: str = SCHEMA_REVISION
    sources_directory: str = "sources"
    derived_directory: str = "derived"
    created_at: datetime


class StoredCapture(Capture):
    packet_count: int
    diagnostics: dict[str, int]
    import_settings: IndexSettings
    engine_version: str


def project_record(row: ProjectRow) -> Project:
    return Project(
        id=row.id, name=row.name, format_version=row.format_version, created_at=row.created_at
    )


def capture_record(row: CaptureRow) -> StoredCapture:
    return StoredCapture(**{key: getattr(row, key) for key in StoredCapture.model_fields})


class ProjectStore:
    def __init__(self, engine, root: Path):
        self.engine = engine
        self.root = root.resolve()
        self._verified = {}
        self._verification_lock = threading.Lock()

    def directory(self, project_id: UUID) -> Path:
        path = self.root / str(project_id)
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise StorageError("Project directory escapes managed root")
        return path

    def safe_path(self, project_id: UUID, relative: str) -> Path:
        directory = self.directory(project_id)
        candidate = directory / relative
        if (
            Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or not candidate.resolve().is_relative_to(directory)
        ):
            raise StorageError("Project member escapes project directory")
        # Sources/staging must never follow user-created symlinks, even within root.
        for part in (candidate, *candidate.parents):
            if part == directory.parent:
                break
            if part.is_symlink():
                raise StorageError("Symlinks are not allowed in project storage")
        return candidate

    def create(self, name: str) -> Project:
        project = Project(id=uuid4(), name=name.strip(), created_at=datetime.now(UTC))
        directory = self.directory(project.id)
        directory.mkdir(parents=True)
        try:
            for child in ("sources", "derived", ".staging"):
                (directory / child).mkdir()
            manifest = ProjectManifest(project_id=project.id, created_at=project.created_at)
            with (directory / "manifest.json").open("x") as file:
                file.write(manifest.model_dump_json(indent=2) + "\n")
                file.flush()
                os.fsync(file.fileno())
            with Session(self.engine) as db, db.begin():
                db.add(ProjectRow(**project.model_dump(), directory=str(project.id)))
        except Exception:
            # Only this newly generated directory; never an existing project.
            shutil.rmtree(directory)
            raise
        return project

    def get(self, project_id: UUID) -> Project:
        with Session(self.engine) as db:
            row = db.get(ProjectRow, project_id)
            if row is None:
                raise KeyError(project_id)
            project = project_record(row)
        path = self.safe_path(project_id, "manifest.json")
        try:
            manifest = ProjectManifest.model_validate_json(path.read_text())
        except (OSError, ValueError) as exc:
            raise StorageError(
                "Project manifest is missing or invalid; sources were not modified"
            ) from exc
        if (
            manifest.project_id != project.id
            or manifest.format != "protocol-lab-project"
            or manifest.format_version != FORMAT_VERSION
            or manifest.metadata_schema_revision != SCHEMA_REVISION
            or manifest.sources_directory != "sources"
            or manifest.derived_directory != "derived"
        ):
            raise StorageError(
                "Project manifest identity/version is incompatible; sources were not modified"
            )
        return project

    def list_projects(self, offset: int, limit: int) -> list[Project]:
        with Session(self.engine) as db:
            return [
                project_record(row)
                for row in db.scalars(
                    select(ProjectRow)
                    .order_by(ProjectRow.created_at, ProjectRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def captures(self, project_id: UUID, offset: int, limit: int) -> list[StoredCapture]:
        self.get(project_id)
        with Session(self.engine) as db:
            return [
                capture_record(row)
                for row in db.scalars(
                    select(CaptureRow)
                    .where(CaptureRow.project_id == project_id)
                    .order_by(CaptureRow.imported_at, CaptureRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def get_capture(self, capture_id: UUID) -> StoredCapture:
        with Session(self.engine) as db:
            row = db.get(CaptureRow, capture_id)
            if row is None:
                raise KeyError(capture_id)
            return capture_record(row)

    def packets(self, capture_id: UUID, offset: int, limit: int) -> list[IndexedPacket]:
        self.get_capture(capture_id)
        with Session(self.engine) as db:
            rows = db.scalars(
                select(PacketRow)
                .where(PacketRow.capture_id == capture_id)
                .order_by(PacketRow.index)
                .offset(offset)
                .limit(limit)
            )
            return [IndexedPacket.model_validate(row.metadata_json) for row in rows]

    def packet(self, packet_id: UUID) -> IndexedPacket:
        with Session(self.engine) as db:
            row = db.get(PacketRow, packet_id)
            if row is None:
                raise KeyError(packet_id)
            packet = IndexedPacket.model_validate(row.metadata_json)
        capture = self.get_capture(packet.capture_id)
        self.get(capture.project_id)
        return packet

    def finalize_import(
        self,
        project_id: UUID,
        capture_id: UUID,
        source: Path,
        index: Path,
        checksum: str,
        file_format: str,
        settings: IndexSettings,
        summary: dict,
    ) -> dict:
        self.get(project_id)
        if sha256_file(source) != checksum:
            raise StorageError("Staged source checksum changed; no capture published")
        relative = f"sources/{checksum}.{file_format}"
        destination = self.safe_path(project_id, relative)
        with Session(self.engine) as db, db.begin():
            # Serialize import publication per project; unique constraint is a second guard.
            key = int.from_bytes(project_id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            existing = db.scalar(
                select(CaptureRow).where(
                    CaptureRow.project_id == project_id, CaptureRow.sha256 == checksum
                )
            )
            if existing:
                original = self.safe_path(project_id, existing.relative_path)
                if not original.exists() or sha256_file(original) != existing.sha256:
                    raise StorageError("Existing source checksum mismatch; duplicate not accepted")
                return {
                    "outcome": "already_imported",
                    "capture_id": str(existing.id),
                    "checksum_policy": existing.checksum_policy,
                    "requested_checksum_policy": settings.checksum_policy,
                }
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise StorageError("Source destination checksum mismatch; refusing overwrite")
            else:
                # No replace/overwrite. Source and destination are on the same filesystem.
                os.link(source, destination)
                destination.chmod(0o444)
            db.add(
                CaptureRow(
                    id=capture_id,
                    project_id=project_id,
                    sha256=checksum,
                    format=file_format,
                    relative_path=relative,
                    size_bytes=source.stat().st_size,
                    checksum_policy=settings.checksum_policy,
                    imported_at=datetime.now(UTC),
                    packet_count=summary["packet_count"],
                    diagnostics=summary["diagnostics"],
                    import_settings=settings.model_dump(),
                    engine_version=__version__,
                )
            )
            db.flush()
            batch = []
            count = 0
            with index.open() as file:
                for line in file:
                    packet = IndexedPacket.model_validate_json(line)
                    if packet.capture_id != capture_id or packet.index != count:
                        raise CaptureError("Invalid staged packet index; no capture published")
                    batch.append(
                        {
                            "id": packet.id,
                            "capture_id": capture_id,
                            "index": packet.index,
                            "metadata_json": packet.model_dump(mode="json"),
                        }
                    )
                    count += 1
                    if len(batch) == 1000:
                        db.execute(insert(PacketRow), batch)
                        batch = []
                if batch:
                    db.execute(insert(PacketRow), batch)
            if count != summary["packet_count"]:
                raise CaptureError("Staged packet count mismatch; no capture published")
        # DB transaction succeeded. Orphaned immutable source after a failed transaction is
        # safe and reused by checksum on retry; never delete captured sources automatically.
        return {"outcome": "imported", "capture_id": str(capture_id), **summary}

    def verify_source(self, capture_id: UUID) -> dict:
        capture = self.get_capture(capture_id)
        source = self.safe_path(capture.project_id, capture.relative_path)
        try:
            with self._verification_lock:
                stat = source.stat()
                signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
                key = (capture.id, capture.sha256)
                if self._verified.get(key) != signature:
                    digest = sha256_file(source)
                    after = source.stat()
                    after_signature = (
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                    if digest != capture.sha256 or after_signature != signature:
                        raise StorageError(
                            "Capture source checksum mismatch; index is not verified"
                        )
                    self._verified[key] = signature
        except OSError as exc:
            raise StorageError("Capture source is unavailable; index is retained") from exc
        return {"capture_id": str(capture.id), "sha256": capture.sha256, "status": "verified"}

    def packet_bytes(self, packet_id, offset, length):
        packet = self.packet(packet_id)
        if not 1 <= length <= 4096 or offset < 0 or offset + length > packet.captured_length:
            raise ValueError("Packet range must be within captured bytes, length 1..4096")
        capture = self.get_capture(packet.capture_id)
        self.verify_source(capture.id)
        with self.safe_path(capture.project_id, capture.relative_path).open("rb") as source:
            source.seek(packet.file_offset + offset)
            data = source.read(length)
        if len(data) != length:
            raise StorageError("Packet range unavailable; source index retained")
        return dict(packet_id=str(packet_id), offset=offset, length=length, data_hex=data.hex())
