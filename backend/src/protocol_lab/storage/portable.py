"""Versioned, project-scoped PostgreSQL snapshots and verified portable file bundles.

Snapshots contain data, never executable SQL. All tables are read under one
REPEATABLE READ transaction; restores insert into a migrated local PostgreSQL.
"""

import hashlib
import json
import os
import shutil
import stat
import zipfile
from datetime import datetime
from decimal import Decimal
from pathlib import PurePosixPath
from uuid import UUID

from pydantic import Field, model_validator
from sqlalchemy import DateTime, Numeric, Uuid, func, insert, or_, select, text, update

from protocol_lab.capture.index import WorkCancelled, sha256_file
from protocol_lab.domain.models import Record
from protocol_lab.storage.database import Base
from protocol_lab.storage.projects import ProjectManifest, StorageError

SNAPSHOT_REVISION = "0007_inference"
LEGACY_REVISION = "0006_validation"
MAX_MEMBERS = 20000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_ROWS = 2_000_000
MAX_LINE_BYTES = 32 * 1024 * 1024
TABLES = {table.name: table for table in Base.metadata.sorted_tables}
INFERENCE_TABLES = {name for name in TABLES if name.startswith("inference_")}


class Member(Record):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=MAX_MEMBER_BYTES)


class Bundle(Record):
    format: str = "protocol-lab-bundle"
    format_version: int = 2
    metadata_schema_revision: str = SNAPSHOT_REVISION
    project_id: UUID
    members: dict[str, Member]
    table_counts: dict[str, int]

    @model_validator(mode="after")
    def compatible(self):
        if self.format != "protocol-lab-bundle" or (
            self.format_version,
            self.metadata_schema_revision,
        ) not in {(1, LEGACY_REVISION), (2, SNAPSHOT_REVISION)}:
            raise ValueError("Unsupported portable format/schema revision")
        inventory = set(TABLES) - INFERENCE_TABLES if self.format_version == 1 else set(TABLES)
        if set(self.table_counts) != inventory or any(n < 0 for n in self.table_counts.values()):
            raise ValueError("Snapshot table inventory is incompatible")
        if sum(self.table_counts.values()) > MAX_ROWS or len(self.members) > MAX_MEMBERS:
            raise ValueError("Snapshot exceeds protective row/member limits")
        if sum(m.size_bytes for m in self.members.values()) > MAX_TOTAL_BYTES:
            raise ValueError("Bundle exceeds 2 GiB expanded limit")
        if not {"manifest.json", "metadata.jsonl"} <= self.members.keys():
            raise ValueError("Bundle lacks project manifest or metadata snapshot")
        for name in self.members:
            member_path(name)
        return self


def member_path(name):
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or any(p in {"", ".", ".."} for p in name.split("/"))
        or str(path) != name
    ):
        raise StorageError(f"Unsafe project member: {name!r}")
    if name not in {"manifest.json", "metadata.jsonl", "bundle.json"} and (
        path.parts[0] not in {"sources", "derived"} or len(path.parts) < 2
    ):
        raise StorageError(f"Unsupported project member: {name!r}")
    return path


def scoped(table, project_id):
    if table.name == "projects":
        return table.c.id == project_id
    if "project_id" in table.c:
        return table.c.project_id == project_id
    conditions = []
    for fk in table.foreign_keys:
        parent = fk.column.table
        if parent is not table:
            condition = fk.parent.in_(select(fk.column).where(scoped(parent, project_id)))
            # Optional references must not silently drop discovery evidence or diagnoses.
            conditions.append(
                or_(fk.parent.is_(None), condition) if fk.parent.nullable else condition
            )
    if not conditions:
        raise StorageError(f"Table {table.name} has no project ownership path")
    from sqlalchemy import and_

    return and_(*conditions)


def encoded(value):
    if isinstance(value, (UUID, Decimal)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Unsupported snapshot value type: {type(value).__name__}")


def decoded(table, row):
    if set(row) != set(table.c.keys()):
        raise StorageError(f"Snapshot columns mismatch in {table.name}")
    result = dict(row)
    for column in table.c:
        value = result[column.name]
        if value is None:
            if not column.nullable:
                raise StorageError(f"Null snapshot value: {table.name}.{column.name}")
        elif isinstance(column.type, Uuid):
            result[column.name] = UUID(value)
        elif isinstance(column.type, DateTime):
            result[column.name] = datetime.fromisoformat(value)
            if result[column.name].tzinfo is None:
                raise StorageError("Snapshot timestamp lacks timezone")
        elif isinstance(column.type, Numeric):
            result[column.name] = Decimal(value)
    metadata = result.get("metadata_json")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise StorageError("Snapshot metadata must be an object")
        for key in ("id", "project_id", "capture_id", "stream_id", "session_id", "parent_id"):
            if (
                key in metadata
                and key in result
                and metadata[key] != (str(result[key]) if result[key] is not None else None)
            ):
                raise StorageError(f"Snapshot metadata identity mismatch: {table.name}.{key}")
    return result


def validate_metadata(name, row):
    # Validate with the runtime contracts, without changing the serialized snapshot.
    from protocol_lab.capture.index import IndexedPacket
    from protocol_lab.domain.models import Observation
    from protocol_lab.framing.engine import Piece
    from protocol_lab.inference.models import InferenceCandidate, InferenceRun
    from protocol_lab.inference.results import EvaluationRecord
    from protocol_lab.interpretation.document import load_model
    from protocol_lab.interpretation.engine import MessageResult
    from protocol_lab.interpretation.schema import content_hash
    from protocol_lab.research.action_logs import ActionEvent
    from protocol_lab.research.hypotheses import StoredHypothesis
    from protocol_lab.storage.framing import RunView
    from protocol_lab.storage.interpretations import DecodeRun, StoredInterpretation
    from protocol_lab.storage.projects import Project, StoredCapture
    from protocol_lab.storage.research import StoredLog
    from protocol_lab.tcp.reassembly import RebuiltSession, RebuiltStream, Reconstruction, Span
    from protocol_lab.validation.models import StoredCorpus, ValidationItem, ValidationRun

    models = {
        "packets": IndexedPacket,
        "observations": Observation,
        "actions": ActionEvent,
        "hypothesis_versions": StoredHypothesis,
        "tcp_sessions": RebuiltSession,
        "tcp_streams": RebuiltStream,
        "tcp_spans": Span,
        "framing_runs": RunView,
        "framing_pieces": Piece,
        "interpretation_versions": StoredInterpretation,
        "interpretation_runs": DecodeRun,
        "interpretation_results": MessageResult,
        "corpus_versions": StoredCorpus,
        "validation_runs": ValidationRun,
        "validation_results": ValidationItem,
        "inference_runs": InferenceRun,
        "inference_candidates": InferenceCandidate,
        "inference_evaluations": EvaluationRecord,
    }
    if name == "projects":
        Project.model_validate({key: row[key] for key in Project.model_fields})
    elif name == "captures":
        StoredCapture.model_validate({key: row[key] for key in StoredCapture.model_fields})
    elif name == "action_logs":
        StoredLog.model_validate(
            {
                **row["metadata_json"],
                "clock_offset_ns": str(row["clock_offset_ns"]),
                "clock_revision": row["clock_revision"],
            }
        )
    elif name == "reconstructions":
        Reconstruction.model_validate({**row["metadata_json"], "sessions": []})
    elif name in models:
        models[name].model_validate(row["metadata_json"])
    if name == "inference_runs":
        run = InferenceRun.model_validate(row["metadata_json"])
        if (
            run.id != row["id"]
            or run.snapshot.project_id != row["project_id"]
            or run.snapshot.corpus.id != row["corpus_version_id"]
            or run.parent_id != row["parent_id"]
        ):
            raise StorageError("Inference snapshot ownership/identity mismatch")
    elif name == "inference_candidates":
        candidate = InferenceCandidate.model_validate(row["metadata_json"])
        if (
            candidate.run_id != row["run_id"]
            or candidate.family != row["family"]
            or row["rank"] < 0
        ):
            raise StorageError("Inference candidate index mismatch")
    elif name == "inference_evaluations":
        evaluation = EvaluationRecord.model_validate(row["metadata_json"]).evaluation
        if (
            evaluation.id != row["id"]
            or evaluation.candidate_id != row["candidate_id"]
            or evaluation.snapshot.project_id != row["project_id"]
            or evaluation.snapshot.corpus.id != row["corpus_version_id"]
        ):
            raise StorageError("Inference evaluation snapshot mismatch")
    elif name == "inference_evidence":
        if (
            row["file_offset"] < 0
            or not 0 < row["length"] <= 4 * 1024 * 1024
            or row["ordinal"] < 0
            or row["status"] not in {"passed", "failed", "unknown", "ambiguous", "not_applicable"}
        ):
            raise StorageError("Inference evidence index outside protective bounds")
    if name == "interpretation_versions":
        from uuid import uuid5

        version = StoredInterpretation.model_validate(row["metadata_json"])
        model = load_model(version.document_json)
        if (
            content_hash(model) != version.content_sha256
            or uuid5(version.model_id, version.content_sha256) != version.id
        ):
            raise StorageError("Imported interpretation content hash/identity mismatch")


def check_cancel(cancelled):
    if cancelled():
        raise WorkCancelled


def copy_checked(
    source, destination, expected=None, cancelled=lambda: False, progress=lambda n: None
):
    if source.is_symlink() or not source.is_file():
        raise StorageError(f"Project file missing or symlink: {source.name}")
    before_stat = source.stat()
    before = (
        before_stat.st_ino,
        before_stat.st_size,
        before_stat.st_mtime_ns,
        before_stat.st_ctime_ns,
    )
    digest, size = hashlib.sha256(), 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_file, destination.open("xb") as output:
        while chunk := input_file.read(1024 * 1024):
            check_cancel(cancelled)
            digest.update(chunk)
            size += len(chunk)
            if size > MAX_MEMBER_BYTES:
                raise StorageError(f"Project member exceeds 512 MiB: {source.name}")
            output.write(chunk)
            progress(size)
        output.flush()
        os.fsync(output.fileno())
    member = Member(sha256=digest.hexdigest(), size_bytes=size)
    after = source.stat()
    signature = (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if signature != before or (expected and member.sha256 != expected):
        raise StorageError(f"Project checksum changed/mismatch: {source.name}")
    return member


def check_schema(connection):
    revisions = connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
    if revisions != [SNAPSHOT_REVISION]:
        raise StorageError("Destination/source PostgreSQL requires alembic upgrade head (0007)")


def snapshot(
    projects,
    project_id,
    destination,
    cancelled=lambda: False,
    progress=lambda done, total, message: None,
):
    projects.get(project_id)
    destination.mkdir()
    members, counts, files = {}, {}, {}
    with (
        projects.engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
        conn.begin(),
    ):
        conn.execute(text("SET TRANSACTION READ ONLY"))
        check_schema(conn)
        row_total = sum(
            conn.scalar(select(func.count()).select_from(table).where(scoped(table, project_id)))
            for table in TABLES.values()
        )
        if row_total > MAX_ROWS:
            raise StorageError("Snapshot exceeds 2000000 rows")
        progress(0, row_total, "Reading consistent PostgreSQL snapshot (rows)")
        metadata = destination / "metadata.jsonl"
        rows = 0
        with metadata.open("x") as output:
            for name, table in TABLES.items():
                counts[name] = 0
                query = select(table).where(scoped(table, project_id)).order_by(table.c.id)
                for row in conn.execute(query.execution_options(yield_per=1000)).mappings():
                    check_cancel(cancelled)
                    counts[name] += 1
                    rows += 1
                    if rows > MAX_ROWS:
                        raise StorageError("Snapshot exceeds 2000000 rows")
                    line = (
                        json.dumps(
                            {"table": name, "row": dict(row)},
                            default=encoded,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    if len(line.encode()) > MAX_LINE_BYTES:
                        raise StorageError(f"Snapshot row exceeds 32 MiB: {name}")
                    output.write(line)
                    if "relative_path" in row:
                        files[row["relative_path"]] = row["sha256"]
                    if name == "action_logs":
                        files[row["metadata_json"]["relative_path"]] = row["sha256"]
                    if rows % 1000 == 0:
                        progress(rows, row_total, "Reading consistent PostgreSQL snapshot (rows)")
                if output.tell() > MAX_MEMBER_BYTES:
                    raise StorageError("Metadata snapshot exceeds 512 MiB")
            output.flush()
            os.fsync(output.fileno())
        if counts["projects"] != 1:
            raise StorageError("Project disappeared during snapshot")
        members["metadata.jsonl"] = Member(
            sha256=sha256_file(metadata), size_bytes=metadata.stat().st_size
        )
        file_total = metadata.stat().st_size + sum(
            projects.safe_path(project_id, name).stat().st_size
            for name in ["manifest.json", *files]
        )
        if len(files) + 2 > MAX_MEMBERS or file_total > MAX_TOTAL_BYTES:
            raise StorageError("Snapshot exceeds file/expanded-size limits")
        copied = metadata.stat().st_size
        for name, expected in [("manifest.json", None), *sorted(files.items())]:
            member_path(name)
            members[name] = copy_checked(
                projects.safe_path(project_id, name),
                destination / name,
                expected,
                cancelled,
                lambda n, base=copied: progress(
                    base + n, file_total, "Copying verified project files (bytes)"
                ),
            )
            copied += members[name].size_bytes
            if (
                len(members) > MAX_MEMBERS
                or sum(m.size_bytes for m in members.values()) > MAX_TOTAL_BYTES
            ):
                raise StorageError("Snapshot exceeds file/expanded-size limits")
        bundle = Bundle(project_id=project_id, members=members, table_counts=counts)
        (destination / "bundle.json").write_text(bundle.model_dump_json(indent=2) + "\n")
    check_cancel(cancelled)
    return bundle


def pack(directory, archive, cancelled=lambda: False, progress=lambda done, total, message: None):
    bundle = verify_bundle(directory, cancelled)
    total = (
        sum(m.size_bytes for m in bundle.members.values())
        + (directory / "bundle.json").stat().st_size
    )
    done = 0
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zip_file:
        for name in ["bundle.json", *sorted(bundle.members)]:
            with (
                (directory / name).open("rb") as source,
                zip_file.open(name, "w", force_zip64=True) as out,
            ):
                while chunk := source.read(1024 * 1024):
                    check_cancel(cancelled)
                    out.write(chunk)
                    done += len(chunk)
                    progress(done, total, "Packing verified archive (bytes)")
    return bundle


def unpack(archive, directory, cancelled=lambda: False, progress=lambda done, total, message: None):
    directory.mkdir()
    try:
        with zipfile.ZipFile(archive) as source:
            infos = source.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or len(names) > MAX_MEMBERS + 1:
                raise StorageError("Archive contains duplicate/too many members")
            total = 0
            done = 0
            for info in infos:
                member_path(info.filename)
                mode = info.external_attr >> 16
                if (
                    stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                    or info.is_dir()
                    or info.flag_bits & 1
                ):
                    raise StorageError("Archive contains links, directories or encrypted members")
                if info.file_size > MAX_MEMBER_BYTES:
                    raise StorageError("Archive member exceeds 512 MiB")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise StorageError("Archive expanded size exceeds 2 GiB")
            for info in infos:
                target = directory / info.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(info) as file, target.open("xb") as out:
                    size = 0
                    while chunk := file.read(1024 * 1024):
                        check_cancel(cancelled)
                        size += len(chunk)
                        if size > info.file_size or size > MAX_MEMBER_BYTES:
                            raise StorageError("Archive expanded member size mismatch")
                        out.write(chunk)
                        done += len(chunk)
                        progress(done, total, "Extracting bounded archive (bytes)")
        return verify_bundle(directory, cancelled)
    except (zipfile.BadZipFile, OSError) as exc:
        raise StorageError("Archive is malformed/unavailable; no project restored") from exc


def verify_bundle(directory, cancelled=lambda: False):
    try:
        if directory.is_symlink():
            raise StorageError("Bundle root must not be a symlink")
        manifest_path = directory / "bundle.json"
        if manifest_path.is_symlink() or manifest_path.stat().st_size > 8 * 1024 * 1024:
            raise StorageError("Bundle manifest exceeds limit or is a symlink")
        bundle = Bundle.model_validate_json(manifest_path.read_text())
        expected_names = {"bundle.json", *bundle.members}
        actual = set()
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise StorageError("Bundle contains a symlink")
            if path.is_file():
                actual.add(path.relative_to(directory).as_posix())
        if actual != expected_names:
            raise StorageError("Bundle contains missing or unlisted files")
        for name, member in bundle.members.items():
            check_cancel(cancelled)
            path = directory / name
            # Guard components inside the bundle; OS aliases such as /var are allowed.
            if any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(directory)):
                raise StorageError(f"Bundle symlink: {name}")
            if path.stat().st_size != member.size_bytes or sha256_file(path) != member.sha256:
                raise StorageError(f"Bundle checksum mismatch: {name}")
        project = ProjectManifest.model_validate_json((directory / "manifest.json").read_text())
        if (
            project.project_id != bundle.project_id
            or project.format != "protocol-lab-project"
            or project.format_version != 1
            or project.metadata_schema_revision != "0001_capture_storage"
            or project.sources_directory != "sources"
            or project.derived_directory != "derived"
        ):
            raise StorageError("Project manifest identity/version mismatch")
        return bundle
    except (ValueError, OSError) as exc:
        if isinstance(exc, StorageError):
            raise
        raise StorageError("Bundle manifest invalid or missing; no project restored") from exc


def rows(directory):
    with (directory / "metadata.jsonl").open() as file:
        while line := file.readline(MAX_LINE_BYTES + 1):
            if len(line.encode()) > MAX_LINE_BYTES:
                raise StorageError("Snapshot row exceeds 32 MiB")
            try:
                value = json.loads(line)
                if set(value) != {"table", "row"} or value["table"] not in TABLES:
                    raise ValueError
                yield value["table"], decoded(TABLES[value["table"]], value["row"])
            except (TypeError, KeyError, ValueError) as exc:
                raise StorageError("Snapshot row malformed/incompatible") from exc


def restore(projects, directory, cancelled=lambda: False):
    bundle = verify_bundle(directory, cancelled)
    if bundle.table_counts["projects"] != 1:
        raise StorageError("Snapshot must contain exactly one project")
    project_id = bundle.project_id
    destination = projects.directory(project_id)
    owned = False
    counts = {name: 0 for name in TABLES}
    expected_counts = {name: bundle.table_counts.get(name, 0) for name in TABLES}
    parent_updates = []
    refs = {"manifest.json", "metadata.jsonl"}
    try:
        with projects.engine.begin() as conn:
            check_schema(conn)
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": int.from_bytes(project_id.bytes[:8], "big", signed=True)},
            )
            if conn.scalar(
                select(TABLES["projects"].c.id).where(TABLES["projects"].c.id == project_id)
            ):
                raise StorageError(
                    "Project identity already exists; restore refuses to merge/overwrite"
                )
            if destination.exists():
                raise StorageError(
                    "Destination directory already exists; restore refuses overwrite"
                )
            last = -1
            batch = []
            current = None

            def flush():
                if batch:
                    conn.execute(insert(TABLES[current]), batch)
                    batch.clear()

            for name, row in rows(directory):
                check_cancel(cancelled)
                position = list(TABLES).index(name)
                if position < last:
                    raise StorageError("Snapshot tables are out of dependency order")
                if name != current:
                    flush()
                    current, last = name, position
                validate_metadata(name, row)
                counts[name] += 1
                if counts[name] > expected_counts[name]:
                    raise StorageError("Snapshot row count mismatch")
                if name == "projects" and (
                    row["id"] != project_id
                    or row["directory"] != str(project_id)
                    or row["format_version"] != 1
                ):
                    raise StorageError("Snapshot project identity mismatch")
                if "project_id" in row and row["project_id"] != project_id:
                    raise StorageError("Snapshot contains another project")
                if "relative_path" in row:
                    path = row["relative_path"]
                    member_path(path)
                    if path not in bundle.members or row["sha256"] != bundle.members[path].sha256:
                        raise StorageError("Snapshot file reference/hash mismatch")
                    refs.add(path)
                if name == "action_logs":
                    path = row["metadata_json"]["relative_path"]
                    member_path(path)
                    if path not in bundle.members or row["sha256"] != bundle.members[path].sha256:
                        raise StorageError("Action-log file reference/hash mismatch")
                    refs.add(path)
                if row.get("parent_id"):
                    parent_updates.append((name, row["id"], row["parent_id"]))
                    row["parent_id"] = None
                batch.append(row)
                if len(batch) >= 500:
                    flush()
            flush()
            if counts != expected_counts or refs != set(bundle.members):
                raise StorageError(
                    "Snapshot inventory does not match complete database/file snapshot"
                )
            for name, id, parent in parent_updates:
                conn.execute(
                    update(TABLES[name]).where(TABLES[name].c.id == id).values(parent_id=parent)
                )
            # Foreign keys must resolve inside this snapshot, not unrelated research.
            for name, table in TABLES.items():
                amount = conn.scalar(
                    select(func.count()).select_from(table).where(scoped(table, project_id))
                )
                if amount != counts[name]:
                    raise StorageError(f"Snapshot foreign-key ownership mismatch: {name}")
                for fk in table.foreign_keys:
                    if fk.column.table is not table:
                        bad = conn.scalar(
                            select(func.count())
                            .select_from(table)
                            .where(
                                scoped(table, project_id),
                                fk.parent.is_not(None),
                                fk.parent.not_in(
                                    select(fk.column).where(scoped(fk.column.table, project_id))
                                ),
                            )
                        )
                        if bad:
                            raise StorageError(f"Snapshot refers to another project: {name}")
                    if fk.column.table is table:
                        foreign = table.alias("parent")
                        bad = conn.scalar(
                            select(func.count())
                            .select_from(
                                table.join(foreign, fk.parent == foreign.c[fk.column.name])
                            )
                            .where(scoped(table, project_id), foreign.c.project_id != project_id)
                        )
                        if bad:
                            raise StorageError("Snapshot parent refers to another project")
            check_cancel(cancelled)
            destination.mkdir(parents=True)
            owned = True
            for name, member in bundle.members.items():
                if name == "metadata.jsonl":
                    continue
                copy_checked(directory / name, destination / name, member.sha256, cancelled)
                if name != "manifest.json":
                    (destination / name).chmod(0o444)
            (destination / ".staging").mkdir()
            (destination / "sources").mkdir(exist_ok=True)
            (destination / "derived").mkdir(exist_ok=True)
            # Preserve a full, independently openable checkpoint in the restored directory.
            shutil.copytree(directory, destination / "checkpoints" / "restored")
            check_cancel(cancelled)
        return {"outcome": "restored", "project_id": str(project_id)}
    except BaseException:
        if owned:
            shutil.rmtree(destination)
        raise
