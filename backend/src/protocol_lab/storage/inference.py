"""Frozen research inputs and atomic PostgreSQL publication of immutable JSONL evidence."""

import os
from bisect import bisect_right
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid5

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session

from protocol_lab.capture.index import sha256_file
from protocol_lab.domain.models import ByteRange, SourceRange
from protocol_lab.framing.engine import VERSION as FRAMING_VERSION
from protocol_lab.inference.engine import VERSION, StreamData
from protocol_lab.inference.models import (
    CandidateEvidence,
    CandidateInput,
    EngineVersions,
    FramingInput,
    InferenceCandidate,
    InferenceRun,
    InferenceSnapshot,
    InterpretationInput,
    content_hash,
)
from protocol_lab.inference.ranking import VERSION as RANKING_VERSION
from protocol_lab.inference.results import (
    CandidateSummary,
    EvaluationRecord,
    InferenceCurrentness,
    RunSummary,
)
from protocol_lab.interpretation.engine import VERSION as INTERPRETATION_VERSION
from protocol_lab.storage.database import (
    CorpusRow,
    InferenceCandidateRow,
    InferenceEvaluationRow,
    InferenceEvidenceRow,
    InferenceRunRow,
    InterpretationRow,
    PacketRow,
    ReconstructionRow,
)
from protocol_lab.storage.projects import StorageError
from protocol_lab.storage.validation import ValidationStore
from protocol_lab.validation.models import VERSION as VALIDATION_VERSION


def versions():
    return EngineVersions(
        inference=VERSION,
        framing=FRAMING_VERSION,
        interpretation=INTERPRETATION_VERSION,
        validation=VALIDATION_VERSION,
        ranking=RANKING_VERSION,
    )


class InferenceStore:
    def __init__(self, projects):
        self.projects, self.engine = projects, projects.engine
        self.validation = ValidationStore(projects)
        self.framing = self.validation.interpretations.framing

    def freeze(self, project_id, spec, parent_id=None):
        self.projects.get(project_id)
        corpus = self.validation.corpus(spec.corpus_version_id)
        if corpus.project_id != project_id:
            raise ValueError("Inference corpus belongs to another project")
        if spec.logs or spec.parameters:
            raise ValueError("Logs/parameters require A2; they cannot be silently ignored in A1")
        if parent_id and self.get(parent_id).snapshot.project_id != project_id:
            raise ValueError("Parent inference run belongs to another project")
        interpretation = None
        if spec.interpretation_version_id:
            model = self.validation.interpretations.version(spec.interpretation_version_id)
            if model.project_id != project_id:
                raise ValueError("Interpretation belongs to another project")
            interpretation = InterpretationInput(
                id=model.id,
                sha256=model.content_sha256,
                document_json=model.document_json,
            )
        with (
            self.engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn,
            Session(conn) as db,
            db.begin(),
        ):
            sources = self.validation.sources(db, project_id, corpus)
        selected_streams = {s.id for c in sources for s in c.streams if s.included}
        framings = []
        for id in spec.framing_version_ids:
            run = self.framing.get(id)
            if run.stream_id not in selected_streams:
                raise ValueError("Framing is outside the selected project/corpus streams")
            framings.append(
                FramingInput(
                    id=id, sha256=content_hash(run.spec), spec=run.spec, stream_id=run.stream_id
                )
            )
        candidates = []
        for id in spec.candidate_ids:
            candidate = self.candidate(id)
            owner = self.get(candidate.run_id).snapshot.project_id
            if owner != project_id:
                raise ValueError("Candidate belongs to another project")
            candidates.append(
                CandidateInput(id=id, sha256=candidate.rule_sha256, rule=candidate.rule)
            )
        snapshot = InferenceSnapshot(
            project_id=project_id,
            spec=spec,
            corpus=corpus,
            sources=sources,
            interpretation=interpretation,
            framing=tuple(framings),
            candidates=tuple(candidates),
            engines=versions(),
        )
        self.verify_inputs(snapshot)
        return snapshot

    def verify_inputs(self, snapshot):
        if self.validation.corpus(snapshot.corpus.id) != snapshot.corpus:
            raise StorageError("Inference corpus version changed; no result published")
        with Session(self.engine) as db:
            current = self.validation.sources(db, snapshot.project_id, snapshot.corpus)
        if current != snapshot.sources:
            raise StorageError("Inference source/reconstruction changed; no result published")
        for capture in snapshot.sources:
            self.projects.verify_source(capture.id)
            if capture.reconstruction_id:
                with Session(self.engine) as db:
                    row = db.get(ReconstructionRow, capture.reconstruction_id)
                    path = self.projects.safe_path(snapshot.project_id, row.relative_path)
                if sha256_file(path) != capture.reconstruction_sha256:
                    raise StorageError(f"Capture {capture.id}: reconstruction checksum mismatch")
        if snapshot.interpretation:
            model = self.validation.interpretations.version(snapshot.interpretation.id)
            if (
                model.content_sha256 != snapshot.interpretation.sha256
                or model.document_json != snapshot.interpretation.document_json
            ):
                raise StorageError("Frozen interpretation changed")
        for value in snapshot.framing:
            if self.framing.get(value.id).spec != value.spec:
                raise StorageError("Frozen framing changed")
        for value in snapshot.candidates:
            if self.candidate(value.id).rule_sha256 != value.sha256:
                raise StorageError("Frozen candidate changed")

    @contextmanager
    def inputs(self, snapshot):
        with ExitStack() as stack:
            inputs = []
            for capture in snapshot.sources:
                path = self.projects.safe_path(
                    snapshot.project_id, self.projects.get_capture(capture.id).relative_path
                )
                file = stack.enter_context(path.open("rb"))
                for stream in capture.streams:
                    actual = self.framing.tcp.stream(stream.id)
                    spans = list(self.framing.tcp.spans(stream.id))
                    from protocol_lab.framing.source import stream_input

                    def provenance(
                        a, spans=spans, ends=tuple(span.byte_range.end for span in spans)
                    ):
                        result = []
                        for index in range(bisect_right(ends, a.byte_range.start), len(spans)):
                            span = spans[index]
                            if span.byte_range.start >= a.byte_range.end:
                                break
                            left = max(a.byte_range.start, span.byte_range.start)
                            right = min(a.byte_range.end, span.byte_range.end)
                            if left >= right:
                                continue
                            for source in span.sources:
                                delta = left - span.byte_range.start
                                result.append(
                                    SourceRange(
                                        capture_id=source.capture_id,
                                        packet_id=source.packet_id,
                                        stream=a.model_copy(
                                            update={"byte_range": ByteRange(start=left, end=right)}
                                        ),
                                        packet_payload_range=ByteRange(
                                            start=source.packet_payload_range.start + delta,
                                            end=source.packet_payload_range.start
                                            + delta
                                            + right
                                            - left,
                                        ),
                                    )
                                )
                                if len(result) > 1000:
                                    raise StorageError(
                                        "Evidence exceeds 1000 source ranges; narrow the corpus"
                                    )
                        return tuple(result)

                    inputs.append(
                        StreamData(capture, stream, stream_input(actual, spans, file), provenance)
                    )
                    if spans and spans[0].sources:
                        first = spans[0].sources[0]
                        with Session(self.engine) as db:
                            packet = db.get(PacketRow, first.packet_id).metadata_json
                        if packet.get("tcp_sequence") is not None:
                            inputs[-1].wire_identity = (
                                packet["source_ip"],
                                packet["source_port"],
                                packet["destination_ip"],
                                packet["destination_port"],
                            )
                            inputs[-1].sequence_origin = (
                                packet["tcp_sequence"]
                                + bool(packet["tcp_flags"] & 2)
                                + first.packet_payload_range.start
                                - spans[0].byte_range.start
                            ) % (2**32)
            yield inputs

    def _artifact(self, project_id, path, prefix, id):
        sha = sha256_file(path)
        relative = f"derived/{prefix}-{id}-{sha}.jsonl"
        return sha, relative, self.projects.safe_path(project_id, relative)

    def publish(self, snapshot, artifact, summary):
        self.verify_inputs(snapshot)
        artifact = Path(artifact)
        with artifact.open("rb") as file:
            run = InferenceRun.model_validate_json(file.readline())
            # The worker may add only the deterministic final sample to the frozen inputs.
            if run.snapshot.model_copy(update={"sample_anchors": ()}) != snapshot:
                raise StorageError("Inference publication snapshot mismatch")
            candidates = []
            while True:
                position = file.tell()
                line = file.readline()
                if not line:
                    break
                import json

                item = json.loads(line)
                if item["kind"] != "candidate":
                    file.seek(position)
                    break
                candidate = InferenceCandidate.model_validate(item["value"])
                if (
                    candidate.run_id != run.id
                    or candidate.scope.corpus_version_id != snapshot.corpus.id
                ):
                    raise StorageError("Candidate publication identity mismatch")
                candidates.append(candidate)
            if len(candidates) != run.candidate_count or len({c.id for c in candidates}) != len(
                candidates
            ):
                raise StorageError("Candidate inventory mismatch")
            candidate_ids = {c.id for c in candidates}
            if any(not set(c.dependency_ids) <= candidate_ids for c in candidates):
                raise StorageError("Dangling candidate dependency")
            sha, relative, destination = self._artifact(
                snapshot.project_id, artifact, "inference", run.id
            )
            linked = False
            try:
                with Session(self.engine) as db, db.begin():
                    db.add(
                        InferenceRunRow(
                            id=run.id,
                            project_id=snapshot.project_id,
                            corpus_version_id=snapshot.corpus.id,
                            parent_id=run.parent_id,
                            created_at=run.created_at,
                            relative_path=relative,
                            sha256=sha,
                            metadata_json=run.model_dump(mode="json"),
                        )
                    )
                    db.flush()
                    for rank, c in enumerate(candidates):
                        db.add(
                            InferenceCandidateRow(
                                id=c.id,
                                run_id=run.id,
                                rank=rank,
                                family=c.family,
                                metadata_json=c.model_dump(mode="json"),
                            )
                        )
                    db.flush()
                    self._index_evidence(db, file, run.id, snapshot, candidate_ids)
                    if destination.exists():
                        raise StorageError("Inference artifact already exists; refusing overwrite")
                    os.link(artifact, destination)
                    linked = True
                    destination.chmod(0o444)
            except BaseException:
                if linked:
                    destination.unlink(missing_ok=True)
                raise
        return {"outcome": "inferred", "run_id": str(run.id), **summary}

    def _index_evidence(self, db, file, run_id, snapshot, candidate_ids, evaluation_id=None):
        import json

        streams = {s.id: (c.id, s) for c in snapshot.sources for s in c.streams}
        batch, ordinal = [], 0
        while True:
            offset = file.tell()
            line = file.readline(4 * 1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 4 * 1024 * 1024:
                raise StorageError("Inference evidence line exceeds 4 MiB")
            value = json.loads(line)
            if value["kind"] != "evidence":
                raise StorageError("Unexpected inference artifact entry")
            evidence = CandidateEvidence.model_validate(value["value"])
            if evidence.candidate_id not in candidate_ids:
                raise StorageError("Evidence belongs to another candidate")
            if evidence.anchor:
                capture_id, stream = streams.get(evidence.anchor.stream_id, (None, None))
                if (
                    stream is None
                    or evidence.anchor.reconstruction_version != stream.reconstruction_version
                    or evidence.anchor.byte_range.end > stream.extent
                ):
                    raise StorageError("Evidence is outside frozen sources")
                if any(s.capture_id != capture_id for s in evidence.sources):
                    raise StorageError("Evidence source capture mismatch")
            batch.append(
                dict(
                    id=uuid5(evaluation_id or run_id, f"evidence:{ordinal}"),
                    run_id=run_id,
                    candidate_id=evidence.candidate_id,
                    evaluation_id=evaluation_id,
                    ordinal=ordinal,
                    status=evidence.status,
                    file_offset=offset,
                    length=len(line),
                )
            )
            ordinal += 1
            if len(batch) >= 500:
                db.execute(insert(InferenceEvidenceRow), batch)
                batch = []
        if batch:
            db.execute(insert(InferenceEvidenceRow), batch)
        return ordinal

    def get(self, id):
        with Session(self.engine) as db:
            row = db.get(InferenceRunRow, id)
            if row is None:
                raise KeyError(id)
            result = InferenceRun.model_validate(row.metadata_json)
        self.projects.get(result.snapshot.project_id)
        return result

    def runs(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            rows = db.scalars(
                select(InferenceRunRow)
                .where(InferenceRunRow.project_id == project_id)
                .order_by(InferenceRunRow.created_at.desc(), InferenceRunRow.id)
                .offset(offset)
                .limit(limit)
            )
            return [
                RunSummary(
                    id=r.id,
                    created_at=r.created_at,
                    corpus_name=r.metadata_json["snapshot"]["corpus"]["name"],
                    corpus_version_id=r.corpus_version_id,
                    candidate_count=r.metadata_json["candidate_count"],
                    search_complete=r.metadata_json["search_complete"],
                    semantic_sha256=r.metadata_json.get("semantic_sha256"),
                )
                for r in rows
            ]

    def candidate(self, id):
        with Session(self.engine) as db:
            row = db.get(InferenceCandidateRow, id)
            if row is None:
                raise KeyError(id)
            result = InferenceCandidate.model_validate(row.metadata_json)
        self.get(result.run_id)
        return result

    def candidates(self, run_id, offset, limit, family=None):
        self.get(run_id)
        query = select(InferenceCandidateRow).where(InferenceCandidateRow.run_id == run_id)
        if family:
            query = query.where(InferenceCandidateRow.family == family)
        with Session(self.engine) as db:
            total = db.scalar(select(func.count()).select_from(query.subquery()))
            items = [
                CandidateSummary(
                    **{
                        k: v
                        for k, v in row.metadata_json.items()
                        if k in CandidateSummary.model_fields
                    },
                    kind=row.metadata_json["rule"]["kind"],
                )
                for row in db.scalars(
                    query.order_by(InferenceCandidateRow.rank).offset(offset).limit(limit)
                )
            ]
        return items, total

    def evidence(self, candidate_id, offset, limit, status=None, evaluation_id=None):
        import json

        candidate = self.candidate(candidate_id)
        run = self.get(candidate.run_id)
        with Session(self.engine) as db:
            artifact = db.get(InferenceRunRow, run.id)
            if evaluation_id:
                artifact = db.get(InferenceEvaluationRow, evaluation_id)
                if artifact is None or artifact.candidate_id != candidate_id:
                    raise KeyError(evaluation_id)
            path = self.projects.safe_path(run.snapshot.project_id, artifact.relative_path)
            if sha256_file(path) != artifact.sha256:
                raise StorageError("Inference evidence artifact checksum mismatch")
            query = select(InferenceEvidenceRow).where(
                InferenceEvidenceRow.candidate_id == candidate_id,
                InferenceEvidenceRow.evaluation_id == evaluation_id,
            )
            if status:
                query = query.where(InferenceEvidenceRow.status == status)
            total = db.scalar(select(func.count()).select_from(query.subquery()))
            items = []
            with path.open("rb") as file:
                for row in db.scalars(
                    query.order_by(InferenceEvidenceRow.ordinal).offset(offset).limit(limit)
                ):
                    file.seek(row.file_offset)
                    value = json.loads(file.read(row.length))
                    items.append(CandidateEvidence.model_validate(value["value"]))
        return items, total

    def currentness(self, id):
        run = self.get(id)
        snapshot, reasons, details = run.snapshot, [], []
        if snapshot.engines != versions():
            reasons.append("engine_version_changed")
        with Session(self.engine) as db:
            latest = db.scalar(
                select(CorpusRow.id)
                .where(CorpusRow.corpus_id == snapshot.corpus.corpus_id)
                .order_by(CorpusRow.created_at.desc(), CorpusRow.id)
            )
            if latest != snapshot.corpus.id:
                reasons.append("new_corpus_version")
            if snapshot.interpretation:
                old = db.get(InterpretationRow, snapshot.interpretation.id)
                latest = db.scalar(
                    select(InterpretationRow.id)
                    .where(InterpretationRow.model_id == old.model_id)
                    .order_by(InterpretationRow.created_at.desc(), InterpretationRow.id)
                )
                if latest != old.id:
                    reasons.append("new_model_version")
        try:
            self.verify_inputs(snapshot)
        except (ValueError, KeyError, OSError) as exc:
            reasons.append("source_or_reconstruction_changed_or_unavailable")
            details.append(str(exc))
        return InferenceCurrentness(
            checked_at=datetime.now(UTC),
            stale=bool(reasons),
            reasons=tuple(reasons),
            details=tuple(details),
        )

    def freeze_evaluation(self, candidate_id, corpus_id=None):
        from protocol_lab.inference.models import DataSplit

        candidate = self.candidate(candidate_id)
        run = self.get(candidate.run_id)
        if corpus_id is None:
            if not run.snapshot.spec.split.holdout_ids:
                raise ValueError("This run has no held-out sources")
            spec = run.snapshot.spec.model_copy(
                update={
                    "mode": "evaluate",
                    "candidate_ids": (candidate.id,),
                }
            )
            return self.freeze(run.snapshot.project_id, spec), candidate
        corpus = self.validation.corpus(corpus_id)
        spec = run.snapshot.spec.model_copy(
            update={
                "mode": "evaluate",
                "candidate_ids": (candidate.id,),
                "corpus_version_id": corpus_id,
                "framing_version_ids": (),
                "interpretation_version_id": None,
                "excluded_ranges": (),
                "recording_groups": (),
                "split": DataSplit(
                    discovery_ids=corpus.spec.capture_ids,
                    holdout_unavailable_reason="Evaluation executes a previously frozen rule",
                ),
            }
        )
        snapshot = self.freeze(run.snapshot.project_id, spec)
        return snapshot, candidate

    def independence(self, discovery_run_id, snapshot, holdout=False):
        run = self.get(discovery_run_id)

        def sessions(snap, side=None):
            ids = set(getattr(snap.spec.split, side + "_ids")) if side else None
            return {
                stream.session_id
                for capture in snap.sources
                for stream in capture.streams
                if stream.included
                and (
                    ids is None
                    or (capture.id if snap.spec.split.unit == "capture" else stream.session_id)
                    in ids
                )
            }

        target_sessions = sessions(snapshot, "holdout" if holdout else None)
        if target_sessions & sessions(run.snapshot, "discovery"):
            return "exploratory", "Target includes a connection already used for discovery"
        # Separate connections in one capture are valid session splits. Identical
        # captures with *different* identities remain duplicate recording evidence.
        target_captures = {
            c.id: c.sha256
            for c in snapshot.sources
            if any(s.session_id in target_sessions for s in c.streams)
        }
        original_captures = {
            c.id: c.sha256
            for c in run.snapshot.sources
            if any(s.session_id in sessions(run.snapshot, "discovery") for s in c.streams)
        }
        if any(
            a != b and ah == bh
            for a, ah in original_captures.items()
            for b, bh in target_captures.items()
        ):
            return "exploratory", "Target duplicates the original bytes of a discovery recording"
        with Session(self.engine) as db:
            for row in db.scalars(
                select(InferenceRunRow).where(InferenceRunRow.project_id == snapshot.project_id)
            ):
                prior = InferenceRun.model_validate(row.metadata_json).snapshot
                if sessions(prior, "discovery") & target_sessions:
                    return "exploratory", "Target was already used by an earlier discovery run"
            for row in db.scalars(
                select(InferenceEvaluationRow).where(
                    InferenceEvaluationRow.project_id == snapshot.project_id
                )
            ):
                prior = EvaluationRecord.model_validate(row.metadata_json)
                exposed = sessions(
                    prior.evaluation.snapshot, "holdout" if prior.target_side == "holdout" else None
                )
                if exposed & target_sessions:
                    return (
                        "exploratory",
                        "Target connections were already inspected in an evaluation",
                    )
        if snapshot.spec.recording_groups:
            return "unverified", "Recording independence requires researcher review"
        return (
            "independent",
            "Disjoint capture IDs/hashes and no prior discovery/evaluation; "
            "independence is conditional on the declared recording groups; "
            "overlapping recordings with different hashes are not automatically established",
        )

    def publish_evaluation(self, snapshot, artifact, summary):
        self.verify_inputs(snapshot)
        with Path(artifact).open("rb") as file:
            record = EvaluationRecord.model_validate_json(file.readline())
            evaluation = record.evaluation
            if evaluation.snapshot != snapshot:
                raise StorageError("Evaluation snapshot mismatch")
            candidate = self.candidate(evaluation.candidate_id)
            if evaluation.rule_sha256 != candidate.rule_sha256:
                raise StorageError("Evaluation rule hash mismatch")
            sha, relative, destination = self._artifact(
                snapshot.project_id, Path(artifact), "evaluation", evaluation.id
            )
            linked = False
            try:
                with Session(self.engine) as db, db.begin():
                    db.add(
                        InferenceEvaluationRow(
                            id=evaluation.id,
                            candidate_id=candidate.id,
                            project_id=snapshot.project_id,
                            corpus_version_id=snapshot.corpus.id,
                            created_at=record.created_at,
                            relative_path=relative,
                            sha256=sha,
                            metadata_json=record.model_dump(mode="json"),
                        )
                    )
                    db.flush()
                    count = self._index_evidence(
                        db, file, candidate.run_id, snapshot, {candidate.id}, evaluation.id
                    )
                    if count != record.evidence_count:
                        raise StorageError("Evaluation evidence inventory mismatch")
                    os.link(artifact, destination)
                    linked = True
                    destination.chmod(0o444)
            except BaseException:
                if linked:
                    destination.unlink(missing_ok=True)
                raise
        return {"outcome": "evaluated", "evaluation_id": str(evaluation.id), **summary}

    def evaluations(self, candidate_id, offset, limit):
        self.candidate(candidate_id)
        with Session(self.engine) as db:
            return [
                EvaluationRecord.model_validate(v)
                for v in db.scalars(
                    select(InferenceEvaluationRow.metadata_json)
                    .where(InferenceEvaluationRow.candidate_id == candidate_id)
                    .order_by(InferenceEvaluationRow.created_at.desc(), InferenceEvaluationRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def evaluation(self, id):
        with Session(self.engine) as db:
            row = db.get(InferenceEvaluationRow, id)
            if row is None:
                raise KeyError(id)
            result = EvaluationRecord.model_validate(row.metadata_json)
        self.candidate(result.evaluation.candidate_id)
        return result
