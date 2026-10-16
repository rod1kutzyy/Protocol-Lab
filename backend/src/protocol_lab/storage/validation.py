"""Versioned corpus selection, frozen inputs, atomic validation and paged comparisons."""

import hashlib
import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4, uuid5

from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import Session

from protocol_lab.capture.index import sha256_file
from protocol_lab.framing.engine import VERSION as FRAMING_VERSION
from protocol_lab.framing.engine import identity as framing_identity
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.engine import VERSION as INTERPRETATION_VERSION
from protocol_lab.storage.database import (
    ActionLogRow,
    ActionRow,
    CaptureRow,
    CorpusRow,
    InterpretationRow,
    PacketRow,
    ReconstructionRow,
    SessionRow,
    SpanRow,
    StreamRow,
    ValidationResultRow,
    ValidationRunRow,
)
from protocol_lab.storage.interpretations import InterpretationStore
from protocol_lab.storage.projects import StorageError
from protocol_lab.tcp.reassembly import VERSION as TCP_VERSION
from protocol_lab.tcp.reassembly import RebuiltSession
from protocol_lab.validation.engine import (
    CoverageCounter,
    capture_diagnostics,
    compare,
    item_id,
    matches_session,
    reconstruction_diagnostics,
    reconstruction_failures,
    values_hash,
)
from protocol_lab.validation.models import (
    VERSION,
    CaptureSnapshot,
    Comparison,
    Currentness,
    RunSnapshot,
    StoredCorpus,
    StreamSnapshot,
    ValidationItem,
    ValidationRun,
    ValidationRunSummary,
    ValidationSummary,
)


class ValidationStore:
    def __init__(self, projects):
        self.projects, self.engine = projects, projects.engine
        self.interpretations = InterpretationStore(projects)

    def corpus(self, id):
        with Session(self.engine) as db:
            row = db.get(CorpusRow, id)
            if row is None:
                raise KeyError(id)
            result = StoredCorpus.model_validate(row.metadata_json)
        canonical = json.dumps(
            {"name": result.name, "spec": result.spec.model_dump(mode="json")},
            sort_keys=True,
            separators=(",", ":"),
        )
        checksum = hashlib.sha256(canonical.encode()).hexdigest()
        if result.sha256 != checksum or result.id != uuid5(result.corpus_id, checksum):
            raise StorageError("Immutable corpus version checksum mismatch")
        self.projects.get(result.project_id)
        return result

    def save_corpus(self, project_id, body):
        self.projects.get(project_id)
        for capture_id in body.spec.capture_ids:
            if self.projects.get_capture(capture_id).project_id != project_id:
                raise ValueError("Corpus capture belongs to another project")
        parent = self.corpus(body.parent_id) if body.parent_id else None
        if parent and parent.project_id != project_id:
            raise ValueError("Corpus parent belongs to another project")
        corpus_id = parent.corpus_id if parent else uuid4()
        canonical = json.dumps(
            {"name": body.name, "spec": body.spec.model_dump(mode="json")},
            sort_keys=True,
            separators=(",", ":"),
        )
        checksum = hashlib.sha256(canonical.encode()).hexdigest()
        id = uuid5(corpus_id, checksum)
        with Session(self.engine) as db, db.begin():
            db.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": int.from_bytes(id.bytes[:8], "big", signed=True)},
            )
            old = db.get(CorpusRow, id)
            if old:
                return StoredCorpus.model_validate(old.metadata_json)
            result = StoredCorpus(
                id=id,
                corpus_id=corpus_id,
                project_id=project_id,
                sha256=checksum,
                created_at=datetime.now(UTC),
                **body.model_dump(),
            )
            db.add(
                CorpusRow(
                    id=id,
                    corpus_id=corpus_id,
                    project_id=project_id,
                    parent_id=body.parent_id,
                    created_at=result.created_at,
                    metadata_json=result.model_dump(mode="json"),
                )
            )
        return result

    def corpora(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            return [
                StoredCorpus.model_validate(row)
                for row in db.scalars(
                    select(CorpusRow.metadata_json)
                    .where(CorpusRow.project_id == project_id)
                    .order_by(CorpusRow.created_at.desc(), CorpusRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def sources(self, db, project_id, corpus):
        sources = []
        stream_count = 0
        for capture_id in corpus.spec.capture_ids:
            c = db.get(CaptureRow, capture_id)
            if c is None:
                raise KeyError(capture_id)
            if c.project_id != project_id:
                raise ValueError("Corpus capture belongs to another project")
            eligible = db.scalar(
                select(func.count())
                .select_from(PacketRow)
                .where(
                    PacketRow.capture_id == capture_id,
                    PacketRow.metadata_json["eligible_for_reassembly"].as_boolean().is_(True),
                )
            )
            reconstruction = db.get(ReconstructionRow, uuid5(capture_id, TCP_VERSION))
            streams = []
            failures = []
            if reconstruction:
                span_status = SpanRow.metadata_json["status"].astext
                data_stats = {}
                for stream_id, status, amount in db.execute(
                    select(SpanRow.stream_id, span_status, func.sum(SpanRow.end - SpanRow.start))
                    .join(StreamRow, StreamRow.id == SpanRow.stream_id)
                    .join(SessionRow, SessionRow.id == StreamRow.session_id)
                    .where(SessionRow.reconstruction_id == reconstruction.id)
                    .group_by(SpanRow.stream_id, span_status)
                ):
                    data_stats.setdefault(stream_id, {})[status] = int(amount)
                for row in db.scalars(
                    select(SessionRow)
                    .where(SessionRow.reconstruction_id == reconstruction.id)
                    .order_by(SessionRow.id)
                ):
                    session = RebuiltSession.model_validate(row.metadata_json)
                    included = matches_session(corpus.spec, session, row.start_ns, row.end_ns)
                    missing = reconstruction_failures(session, included, corpus.spec.direction)
                    failures.extend(missing)
                    stream_count += len(missing)
                    if stream_count > 10000:
                        raise ValueError("Corpus exceeds 10000 directed streams protective limit")
                    for stream in session.streams:
                        stream_count += 1
                        if stream_count > 10000:
                            raise ValueError(
                                "Corpus exceeds 10000 directed streams protective limit"
                            )
                        streams.append(
                            StreamSnapshot(
                                id=stream.id,
                                session_id=session.id,
                                reconstruction_version=stream.reconstruction_version,
                                reconstruction_policy=stream.reconstruction_policy,
                                extent=stream.extent,
                                direction=stream.direction,
                                data_status_bytes=data_stats.get(stream.id, {}),
                                included=included
                                and (
                                    corpus.spec.direction == "both"
                                    or stream.direction == corpus.spec.direction
                                ),
                            )
                        )
            sources.append(
                CaptureSnapshot(
                    id=c.id,
                    sha256=c.sha256,
                    size_bytes=c.size_bytes,
                    packet_count=c.packet_count,
                    eligible_packets=eligible,
                    checksum_policy=c.checksum_policy,
                    import_settings=c.import_settings,
                    import_engine_version=c.engine_version,
                    diagnostics=c.diagnostics,
                    reconstruction_id=reconstruction.id if reconstruction else None,
                    reconstruction_sha256=reconstruction.sha256 if reconstruction else None,
                    reconstruction_settings=reconstruction.metadata_json.get("settings")
                    if reconstruction
                    else None,
                    reconstruction_engine_version=reconstruction.version
                    if reconstruction
                    else None,
                    streams=tuple(sorted(streams, key=lambda s: str(s.id))),
                    reconstruction_failures=tuple(failures),
                )
            )
        return tuple(sources)

    def freeze_logs(self, db, project_id, log_ids):
        from protocol_lab.research.action_logs import ActionEvent
        from protocol_lab.storage.research import log_record

        if len(set(log_ids)) != len(log_ids):
            raise ValueError("Duplicate validation action log")
        logs, events = [], []
        for log_id in sorted(log_ids, key=str):
            row = db.get(ActionLogRow, log_id)
            if row is None or row.project_id != project_id:
                raise ValueError("Validation action log belongs to another project or is missing")
            record = log_record(row)
            path = self.projects.safe_path(project_id, record.relative_path)
            if sha256_file(path) != record.sha256:
                raise StorageError("Validation action log checksum mismatch")
            logs.append(record.model_dump(mode="json"))
            for metadata in db.scalars(
                select(ActionRow.metadata_json)
                .where(ActionRow.log_id == log_id)
                .order_by(ActionRow.timestamp_ns, ActionRow.id)
                .limit(100001)
            ):
                if len(events) >= 100000:
                    raise ValueError("Validation action logs exceed 100000 events")
                events.append(
                    ActionEvent.model_validate(
                        {
                            **metadata,
                            "timestamp_ns": str(
                                int(metadata["timestamp_ns"]) + int(row.clock_offset_ns)
                            ),
                        }
                    )
                )
        return tuple(logs), tuple(events)

    def freeze(self, project_id, body):
        self.projects.get(project_id)
        corpus = self.corpus(body.corpus_version_id)
        version = self.interpretations.version(body.interpretation_version_id)
        if corpus.project_id != project_id or version.project_id != project_id:
            raise ValueError("Model and corpus must belong to this project")
        model = load_model(version.document_json)
        with (
            self.engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
            Session(conn) as db,
            db.begin(),
        ):
            sources = self.sources(db, project_id, corpus)
            logs, events = self.freeze_logs(db, project_id, body.log_ids)
        return RunSnapshot(
            id=uuid4(),
            project_id=project_id,
            created_at=datetime.now(UTC),
            corpus=corpus,
            interpretation_version_id=version.id,
            model_id=version.model_id,
            model_sha256=version.content_sha256,
            document_json=version.document_json,
            framing=model.framing,
            framing_engine_version=FRAMING_VERSION,
            interpretation_engine_version=INTERPRETATION_VERSION,
            sources=sources,
            action_logs=logs,
            action_events=events,
        )

    def verify_inputs(self, snapshot):
        version = self.interpretations.version(snapshot.interpretation_version_id)
        if (
            version.document_json != snapshot.document_json
            or version.content_sha256 != snapshot.model_sha256
            or self.corpus(snapshot.corpus.id) != snapshot.corpus
        ):
            raise StorageError("Validation model/corpus version changed; no result published")
        with (
            self.engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
            Session(conn) as db,
            db.begin(),
        ):
            current = self.sources(db, snapshot.project_id, snapshot.corpus)
            logs, events = self.freeze_logs(
                db, snapshot.project_id, [UUID(log["id"]) for log in snapshot.action_logs]
            )
        if logs != snapshot.action_logs or events != snapshot.action_events:
            raise StorageError("Frozen validation action log or clock revision changed")
        if current != snapshot.sources:
            changed = [
                str(old.id)
                for old, new in zip(snapshot.sources, current, strict=True)
                if old != new
            ]
            raise StorageError(
                "Validation source/reconstruction changed for captures: "
                + ", ".join(changed)
                + "; no result published"
            )
        for source in snapshot.sources:
            try:
                self.projects.verify_source(source.id)
            except StorageError as exc:
                raise StorageError(f"Capture {source.id}: {exc}") from None
            if source.reconstruction_id:
                with Session(self.engine) as db:
                    row = db.get(ReconstructionRow, source.reconstruction_id)
                    path = self.projects.safe_path(snapshot.project_id, row.relative_path)
                if not path.exists() or sha256_file(path) != source.reconstruction_sha256:
                    raise StorageError(f"Capture {source.id}: reconstruction artifact changed")

    def publish(self, snapshot, artifact: Path, summary):
        self.verify_inputs(snapshot)
        with artifact.open(encoding="utf-8") as file:
            run = ValidationRun.model_validate_json(file.readline())
        if run.snapshot != snapshot:
            raise StorageError("Validation snapshot mismatch")
        checksum = sha256_file(artifact)
        relative = f"derived/validation-{snapshot.id}-{checksum}.jsonl"
        destination = self.projects.safe_path(snapshot.project_id, relative)
        streams = {s.id: (c.id, s) for c in snapshot.sources for s in c.streams}
        cursors = {id: 0 for id in streams}
        seen_captures = set()
        seen_diagnostics = set()
        seen_zero_streams = set()
        expected_failures = {
            item.id: item
            for capture in snapshot.sources
            for item in reconstruction_diagnostics(snapshot.id, capture)
        }
        seen_failures = set()
        capture_ids = {c.id for c in snapshot.sources}
        source_by_id = {c.id: c for c in snapshot.sources}
        framing_ids = {}
        counter = CoverageCounter(snapshot)
        with Session(self.engine) as db, db.begin():
            db.add(
                ValidationRunRow(
                    id=snapshot.id,
                    project_id=snapshot.project_id,
                    corpus_version_id=snapshot.corpus.id,
                    interpretation_version_id=snapshot.interpretation_version_id,
                    created_at=snapshot.created_at,
                    relative_path=relative,
                    sha256=checksum,
                    metadata_json=run.model_dump(mode="json"),
                )
            )
            db.flush()
            batch = []
            with artifact.open(encoding="utf-8") as file:
                next(file)
                for line in file:
                    item = ValidationItem.model_validate_json(line)
                    expected_id = (
                        uuid5(snapshot.id, f"corpus:{item.check_name}:{item.check_ordinal}")
                        if item.kind == "corpus_check"
                        else item_id(
                            snapshot.id,
                            item.capture_id,
                            item.anchor,
                            item.kind,
                            item.stream_id,
                            item.session_id,
                            item.direction,
                        )
                    )
                    if item.capture_id not in capture_ids or item.id != expected_id:
                        raise StorageError("Validation item source identity mismatch")
                    seen_captures.add(item.capture_id)
                    if item.kind == "corpus_check":
                        model = load_model(snapshot.document_json)
                        if item.check_name not in {check.name for check in model.corpus_checks}:
                            raise StorageError("Unknown corpus check result")
                        for evidence_anchor in (item.anchor, *item.related_anchors):
                            if evidence_anchor is None:
                                continue
                            _owner, evidence_stream = streams.get(
                                evidence_anchor.stream_id, (None, None)
                            )
                            if (
                                evidence_stream is None
                                or not evidence_stream.included
                                or (
                                    evidence_anchor.reconstruction_version
                                    != evidence_stream.reconstruction_version
                                    or evidence_anchor.byte_range.end > evidence_stream.extent
                                )
                            ):
                                raise StorageError("Corpus check evidence outside frozen source")
                        if item.fields or item.unknown_ranges:
                            raise StorageError("Corpus checks cannot replace decoded message facts")
                    elif item.kind == "reconstruction_diagnostic":
                        if item != expected_failures.get(item.id) or item.id in seen_failures:
                            raise StorageError("Validation reconstruction diagnosis mismatch")
                        seen_failures.add(item.id)
                    elif item.anchor:
                        capture_id, stream = streams.get(item.anchor.stream_id, (None, None))
                        r = item.anchor.byte_range
                        if (
                            stream is None
                            or item.stream_id != stream.id
                            or capture_id != item.capture_id
                            or stream.session_id != item.session_id
                            or item.anchor.reconstruction_version != stream.reconstruction_version
                            or r.start != cursors[stream.id]
                            or r.end > stream.extent
                        ):
                            raise StorageError("Validation range coverage mismatch")
                        if not stream.included and (
                            item.kind != "excluded"
                            or item.status != "not_applicable"
                            or item.fields
                            or item.unknown_ranges
                        ):
                            raise StorageError("Excluded corpus stream cannot claim parsed results")
                        if stream.included and item.kind == "excluded":
                            raise StorageError("Included corpus stream cannot be silently excluded")
                        if item.kind in {"message", "leftover"}:
                            if stream.id not in framing_ids:
                                framing_ids[stream.id] = str(
                                    framing_identity(
                                        stream.id,
                                        stream.reconstruction_version,
                                        source_by_id[capture_id].sha256,
                                        snapshot.framing,
                                    )
                                )
                            if item.framing_version != framing_ids[stream.id]:
                                raise StorageError("Validation framing identity mismatch")
                        cursors[stream.id] = r.end
                        for anchor in [
                            *(f.anchor for f in item.fields if f.anchor),
                            *(u.anchor for u in item.unknown_ranges),
                        ]:
                            if (
                                anchor.stream_id != stream.id
                                or anchor.reconstruction_version != stream.reconstruction_version
                                or anchor.byte_range.start < r.start
                                or anchor.byte_range.end > r.end
                            ):
                                raise StorageError("Validation field provenance mismatch")
                    elif item.session_id:
                        capture_id, stream = streams.get(item.stream_id, (None, None))
                        if (
                            stream is None
                            or capture_id != item.capture_id
                            or stream.session_id != item.session_id
                            or stream.extent != 0
                        ):
                            raise StorageError("Validation empty-stream source mismatch")
                        seen_zero_streams.add(item.stream_id)
                    elif item.kind != "capture_diagnostic":
                        raise StorageError("Validation item has no source anchor")
                    else:
                        if item.stream_id or item.fields or item.unknown_ranges:
                            raise StorageError("Capture diagnosis cannot manufacture stream fields")
                        seen_diagnostics.add(item.capture_id)
                    counter.add(item)
                    batch.append(
                        dict(
                            id=item.id,
                            run_id=snapshot.id,
                            capture_id=item.capture_id,
                            stream_id=item.stream_id,
                            start=item.anchor.byte_range.start if item.anchor else -1,
                            end=item.anchor.byte_range.end if item.anchor else -1,
                            kind=item.kind,
                            status=item.status,
                            values_sha256=values_hash(item.fields),
                            metadata_json=item.model_dump(mode="json"),
                        )
                    )
                    if len(batch) == 100:
                        db.execute(insert(ValidationResultRow), batch)
                        batch = []
            if (
                seen_captures != capture_ids
                or seen_failures != set(expected_failures)
                or seen_diagnostics
                != {c.id for c in snapshot.sources if any(capture_diagnostics(snapshot.id, c))}
                or any(
                    s.extent == 0 and id not in seen_zero_streams for id, (_, s) in streams.items()
                )
                or any(cursors[id] != s.extent for id, (_, s) in streams.items())
                or counter.result() != run.coverage
                or sum(run.coverage.byte_counts.values()) != run.coverage.stream_bytes
            ):
                raise StorageError("Validation does not account for entire selected corpus")
            if batch:
                db.execute(insert(ValidationResultRow), batch)
            if destination.exists():
                raise StorageError("Validation result already exists; refusing overwrite")
            os.link(artifact, destination)
            destination.chmod(0o444)
        return {"outcome": "validated", "run_id": str(snapshot.id), **summary}

    def get(self, id):
        with Session(self.engine) as db:
            row = db.get(ValidationRunRow, id)
            if row is None:
                raise KeyError(id)
            run = ValidationRun.model_validate(row.metadata_json)
        self.projects.get(run.snapshot.project_id)
        return run

    def runs(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            metadata = ValidationRunRow.metadata_json
            snapshot = metadata["snapshot"]
            query = (
                select(
                    ValidationRunRow.id,
                    ValidationRunRow.project_id,
                    ValidationRunRow.created_at,
                    ValidationRunRow.corpus_version_id,
                    snapshot["corpus"]["corpus_id"].astext,
                    snapshot["corpus"]["name"].astext,
                    ValidationRunRow.interpretation_version_id,
                    snapshot["model_id"].astext,
                    metadata["coverage"],
                )
                .where(ValidationRunRow.project_id == project_id)
                .order_by(ValidationRunRow.created_at.desc(), ValidationRunRow.id)
                .offset(offset)
                .limit(limit)
            )
            return [
                ValidationRunSummary(
                    id=id,
                    project_id=project,
                    created_at=created,
                    corpus_version_id=corpus,
                    corpus_id=group,
                    corpus_name=name,
                    interpretation_version_id=version,
                    model_id=model,
                    coverage=coverage,
                )
                for (
                    id,
                    project,
                    created,
                    corpus,
                    group,
                    name,
                    version,
                    model,
                    coverage,
                ) in db.execute(query)
            ]

    def currentness(self, id):
        run = self.get(id)
        snapshot = run.snapshot
        reasons = []
        details = []
        with Session(self.engine) as db:
            model = db.scalar(
                select(InterpretationRow)
                .where(InterpretationRow.model_id == snapshot.model_id)
                .order_by(InterpretationRow.created_at.desc(), InterpretationRow.id)
            )
            corpus = db.scalar(
                select(CorpusRow)
                .where(CorpusRow.corpus_id == snapshot.corpus.corpus_id)
                .order_by(CorpusRow.created_at.desc(), CorpusRow.id)
            )
        if model.id != snapshot.interpretation_version_id:
            reasons.append("new_model_version")
        if corpus.id != snapshot.corpus.id:
            reasons.append("new_corpus_version")
        if (
            snapshot.engine_version != VERSION
            or snapshot.framing_engine_version != FRAMING_VERSION
            or snapshot.interpretation_engine_version != INTERPRETATION_VERSION
        ):
            reasons.append("engine_version_changed")
        try:
            self.verify_inputs(snapshot)
        except (StorageError, KeyError, ValueError) as exc:
            reasons.append("source_or_reconstruction_changed_or_unavailable")
            details.append(str(exc))
        return Currentness(
            checked_at=datetime.now(UTC),
            details=tuple(details),
            stale=bool(reasons),
            reasons=tuple(reasons),
            latest_model_version_id=model.id,
            latest_corpus_version_id=corpus.id,
        )

    def summaries(self, run_id, offset=0, limit=None, status=None):
        metadata = ValidationResultRow.metadata_json
        query = select(
            metadata.op("-")("fields").op("-")("unknown_ranges"),
            func.jsonb_array_length(metadata["fields"]),
            func.jsonb_array_length(metadata["unknown_ranges"]),
            ValidationResultRow.values_sha256,
        ).where(ValidationResultRow.run_id == run_id)
        if status:
            query = query.where(ValidationResultRow.status == status)
        query = query.order_by(
            ValidationResultRow.capture_id,
            ValidationResultRow.stream_id.asc().nullsfirst(),
            metadata["anchor"]["reconstruction_version"].astext.asc().nullsfirst(),
            ValidationResultRow.start,
            ValidationResultRow.end,
            ValidationResultRow.kind,
            metadata["session_id"].astext.asc().nullsfirst(),
            metadata["direction"].astext.asc().nullsfirst(),
            metadata["check_name"].astext.asc().nullsfirst(),
            metadata["check_ordinal"].as_integer().asc().nullsfirst(),
        ).offset(offset)
        if limit is not None:
            query = query.limit(limit)
        with Session(self.engine) as db:
            for row, fields, unknown, sha in db.execute(query.execution_options(yield_per=1000)):
                yield ValidationSummary.model_validate(
                    {
                        **row,
                        "field_count": fields,
                        "unknown_range_count": unknown,
                        "values_sha256": sha,
                    }
                )

    def results(self, run_id, offset, limit, status=None):
        self.get(run_id)
        return list(self.summaries(run_id, offset, limit, status))

    def result(self, run_id, item_id):
        self.get(run_id)
        with Session(self.engine) as db:
            row = db.get(ValidationResultRow, item_id)
            if row is None or row.run_id != run_id:
                raise KeyError(item_id)
            return ValidationItem.model_validate(row.metadata_json)

    def comparison(self, left_id, right_id, offset, limit):
        left, right = self.get(left_id), self.get(right_id)
        if left.snapshot.project_id != right.snapshot.project_id:
            raise ValueError("Compare runs from the same project")
        counts = Counter()
        page = []
        total = 0
        for item in compare(iter(self.summaries(left_id)), iter(self.summaries(right_id))):
            counts[item.change] += 1
            if offset <= total < offset + limit:
                page.append(item)
            total += 1
        return Comparison(
            left_run_id=left_id,
            right_run_id=right_id,
            same_sources={c.id: c.sha256 for c in left.snapshot.sources}
            == {c.id: c.sha256 for c in right.snapshot.sources},
            counts=dict(counts),
            items=page,
            next_offset=offset + limit if total > offset + limit else None,
        )
