"""Cancellable process adapter for the shared framing engine."""

import os
from pathlib import Path

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.framing.engine import frame
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.framing import FramingStore
from protocol_lab.storage.projects import ProjectStore, StorageError


def framing_worker(send, cancel, database_url, project_root, stream_id, spec, artifact):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(project_root))
        repository = FramingStore(projects)
        stream, capture = repository.context(stream_id)
        projects.verify_source(capture.id)
        last = -65536

        def progress(done, total):
            nonlocal last
            if done - last >= 65536 or done == total:
                send.send(
                    ("progress", dict(completed=done, total=total, message="Framing stream ranges"))
                )
                last = done

        with projects.safe_path(capture.project_id, capture.relative_path).open("rb") as source:
            result = frame(
                stream_id,
                stream.reconstruction_version,
                capture.id,
                capture.sha256,
                repository.input(stream, source),
                spec,
                cancel.is_set,
                progress,
            )
        projects.verify_source(capture.id)
        if cancel.is_set():
            raise WorkCancelled
        with Path(artifact).open("x") as file:
            file.write(result.model_dump_json())
            file.flush()
            os.fsync(file.fileno())
        if cancel.is_set():
            raise WorkCancelled
        send.send(
            (
                "prepared",
                dict(
                    message_count=result.message_count,
                    leftover_bytes=result.leftover_bytes,
                    uncertain_bytes=result.uncertain_bytes,
                    engine_version=result.engine_version,
                ),
            )
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError) as exc:
        send.send(("failed", f"Stream {stream_id}: {exc}; previous framing/evidence remain usable"))
    except Exception:
        send.send(("failed", f"Stream {stream_id}: framing failed; previous results remain usable"))
    finally:
        if engine:
            engine.dispose()
        send.close()
