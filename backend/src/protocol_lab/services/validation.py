"""Cancellable corpus validation in a local process, using the shared engines."""

import os
import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.interpretation.document import load_model
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.storage.database import PacketRow, make_engine
from protocol_lab.storage.projects import ProjectStore, StorageError
from protocol_lab.storage.validation import ValidationStore
from protocol_lab.validation.corpus import CorpusEvaluator, PacketTimeIndex
from protocol_lab.validation.engine import (
    CoverageCounter,
    capture_diagnostics,
    reconstruction_diagnostics,
    validate_stream,
)
from protocol_lab.validation.models import ValidationRun


def validation_worker(send, cancel, database_url, project_root, snapshot, artifact, limits=None):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(project_root))
        repository = ValidationStore(projects)
        repository.verify_inputs(snapshot)
        model = load_model(snapshot.document_json)
        counter = CoverageCounter(snapshot)
        relations = CorpusEvaluator(model, snapshot.id, snapshot.action_events, cancel.is_set)
        active_times = PacketTimeIndex((), {})
        source = None
        done, total = (
            0,
            len(snapshot.sources) + sum(s.extent * 2 for c in snapshot.sources for s in c.streams),
        )
        last = -65536
        budget = ResultBudget(limits or ResultLimits())
        body = Path(artifact).with_suffix(".body")
        with body.open("x", encoding="utf-8") as output:

            def write(item):
                if cancel.is_set():
                    raise WorkCancelled
                line = item.model_dump_json() + "\n"
                budget.consume(line)
                output.write(line)
                counter.add(item)
                relations.add(item, active_times.get(item.anchor), source)

            def progress(completed, _):
                nonlocal last
                value = done + completed
                if value - last >= 65536 or value == total:
                    send.send(
                        (
                            "progress",
                            dict(completed=value, total=total, message="Validating frozen corpus"),
                        )
                    )
                    last = value

            for capture in snapshot.sources:
                if cancel.is_set():
                    raise WorkCancelled
                for item in capture_diagnostics(snapshot.id, capture):
                    write(item)
                for item in reconstruction_diagnostics(snapshot.id, capture):
                    write(item)
                if capture.reconstruction_id:
                    with Session(engine) as db:
                        packet_times = (
                            {
                                packet_id: int(metadata["timestamp_ns"])
                                for packet_id, metadata in db.execute(
                                    select(PacketRow.id, PacketRow.metadata_json).where(
                                        PacketRow.capture_id == capture.id
                                    )
                                )
                                if metadata.get("timestamp_ns") is not None
                            }
                            if model.corpus_checks
                            else {}
                        )
                    source_path = projects.safe_path(
                        snapshot.project_id, projects.get_capture(capture.id).relative_path
                    )
                    with source_path.open("rb") as file:
                        for stream in capture.streams:
                            actual = repository.interpretations.framing.tcp.stream(stream.id)
                            active_times = (
                                PacketTimeIndex(
                                    repository.interpretations.framing.tcp.spans(stream.id),
                                    packet_times,
                                )
                                if model.corpus_checks
                                else PacketTimeIndex((), {})
                            )
                            source = (
                                repository.interpretations.framing.input(actual, file)
                                if stream.included and stream.extent
                                else None
                            )
                            for item in validate_stream(
                                snapshot.id, capture, stream, source, model, cancel.is_set, progress
                            ):
                                write(item)
                            done += stream.extent * 2
                            progress(0, total)
                done += 1
                progress(0, total)
            for item in relations.finish():
                write(item)
        repository.verify_inputs(snapshot)
        if cancel.is_set():
            raise WorkCancelled
        run = ValidationRun(snapshot=snapshot, coverage=counter.result())
        with Path(artifact).open("x", encoding="utf-8") as output, body.open(encoding="utf-8") as source:
            output.write(run.model_dump_json() + "\n")
            shutil.copyfileobj(source, output, 65536)
            output.flush()
            os.fsync(output.fileno())
        if cancel.is_set():
            raise WorkCancelled
        send.send(
            (
                "prepared",
                dict(
                    counts=run.coverage.counts,
                    message_counts=run.coverage.message_counts,
                    engine_version=run.snapshot.engine_version,
                ),
            )
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError) as exc:
        send.send(
            (
                "failed",
                f"Corpus {snapshot.corpus.id}: {exc}; previous evidence/results remain usable",
            )
        )
    except Exception:
        send.send(
            (
                "failed",
                f"Corpus {snapshot.corpus.id}: validation failed; "
                "previous evidence/results remain usable",
            )
        )
    finally:
        if engine:
            engine.dispose()
        send.close()
