"""Cancellable local-process execution of the shared Construct interpreter."""

import os
import shutil
from collections import Counter
from pathlib import Path

from sqlalchemy.orm import Session

from protocol_lab.capture.index import WorkCancelled, sha256_file
from protocol_lab.interpretation.engine import compile_model, parse_message
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.storage.database import FramingRunRow, make_engine
from protocol_lab.storage.interpretations import DecodeRun, InterpretationStore, run_identity
from protocol_lab.storage.projects import ProjectStore, StorageError


def interpretation_worker(
    send,
    cancel,
    database_url,
    project_root,
    framing_id,
    version_id,
    artifact,
    max_result_bytes=256 * 1024 * 1024,
):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(project_root))
        repository = InterpretationStore(projects)
        framing, stream, capture, version, model = repository.context(framing_id, version_id)
        projects.verify_source(capture.id)
        with Session(engine) as db:
            row = db.get(FramingRunRow, framing_id)
            framing_path = projects.safe_path(capture.project_id, row.relative_path)
            framing_checksum = row.sha256
        if sha256_file(framing_path) != framing_checksum:
            raise StorageError("Immutable framing artifact checksum mismatch")
        parser = compile_model(model)
        counts = Counter()
        offset = 0
        budget = ResultBudget(ResultLimits(model.framing.max_pieces, max_result_bytes))
        body = Path(artifact).with_suffix(".body")
        with (
            body.open("x") as output,
            projects.safe_path(capture.project_id, capture.relative_path).open("rb") as source_file,
        ):
            source = repository.framing.input(stream, source_file)
            while True:
                if cancel.is_set():
                    raise WorkCancelled
                pieces = repository.framing.pieces(framing_id, offset, 100)
                if not pieces:
                    break
                for piece in pieces:
                    if cancel.is_set():
                        raise WorkCancelled
                    result = parse_message(model, parser, piece, source, cancel.is_set, stream.direction)
                    line = result.model_dump_json() + "\n"
                    budget.consume(line)
                    output.write(line)
                    counts[result.status] += 1
                offset += len(pieces)
                send.send(
                    (
                        "progress",
                        dict(
                            completed=pieces[-1].anchor.byte_range.end,
                            total=stream.extent,
                            message="Decoding message fields",
                        ),
                    )
                )
        projects.verify_source(capture.id)
        if sha256_file(framing_path) != framing_checksum:
            raise StorageError("Framing artifact changed during interpretation")
        result = DecodeRun(
            id=run_identity(framing_id, version_id),
            framing_run_id=framing_id,
            version_id=version_id,
            content_sha256=version.content_sha256,
            capture_id=capture.id,
            capture_sha256=capture.sha256,
            reconstruction_version=stream.reconstruction_version,
            piece_count=offset,
            counts=dict(counts),
        )
        if cancel.is_set():
            raise WorkCancelled
        with Path(artifact).open("x") as output, body.open() as input_file:
            output.write(result.model_dump_json() + "\n")
            shutil.copyfileobj(input_file, output, 65536)
            output.flush()
            os.fsync(output.fileno())
        if cancel.is_set():
            raise WorkCancelled
        send.send(
            (
                "prepared",
                dict(piece_count=offset, counts=dict(counts), engine_version=result.engine_version),
            )
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError) as exc:
        send.send(
            ("failed", f"Framing {framing_id}: {exc}; previous models/evidence remain usable")
        )
    except Exception:
        send.send(
            (
                "failed",
                f"Framing {framing_id}: interpretation failed; "
                "previous models/evidence remain usable",
            )
        )
    finally:
        if engine:
            engine.dispose()
        send.close()
