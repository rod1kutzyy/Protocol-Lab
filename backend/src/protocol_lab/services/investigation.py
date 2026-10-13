"""Local cancellable log-import and stream-search processes."""

import os
from pathlib import Path

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.research.action_logs import LogError, parse_events
from protocol_lab.research.search import search_known
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.projects import ProjectStore, StorageError
from protocol_lab.storage.reconstruction import ReconstructionStore


def log_worker(send, cancel, source, events_path, log_id, format, mapping):
    try:
        events, summary = parse_events(
            log_id, Path(source).read_bytes(), format, mapping, cancel.is_set
        )
        with Path(events_path).open("x") as file:
            for index, event in enumerate(events):
                if cancel.is_set():
                    raise WorkCancelled
                file.write(event.model_dump_json() + "\n")
                if index % 128 == 0:
                    send.send(
                        (
                            "progress",
                            dict(
                                completed=index,
                                total=len(events),
                                message="Indexing action-log rows",
                            ),
                        )
                    )
            file.flush()
            os.fsync(file.fileno())
        if cancel.is_set():
            raise WorkCancelled
        send.send(("prepared", summary))
    except WorkCancelled:
        send.send(("cancelled", None))
    except LogError as exc:
        send.send(("failed", str(exc)))
    except Exception:
        send.send(("failed", "Action-log import failed; previous project data remains usable"))
    finally:
        send.close()


def search_worker(send, cancel, database_url, project_root, stream_id, pattern, start):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(project_root))
        tcp = ReconstructionStore(projects)
        stream = tcp.stream(stream_id)
        session = tcp.session(stream.session_id)
        capture = projects.get_capture(session.capture_id)
        projects.verify_source(capture.id)
        with projects.safe_path(capture.project_id, capture.relative_path).open("rb") as source:

            def chunks():
                for span in tcp.spans(stream_id):
                    left, right = span.byte_range.start, span.byte_range.end
                    data = None
                    if span.status == "known":
                        source.seek(span.sources[0].file_offset)
                        data = source.read(right - left)
                        if len(data) != right - left:
                            raise StorageError("Search source range unavailable")
                    yield left, right, data

            last_progress = -1

            def progress(position):
                nonlocal last_progress
                if position - last_progress > 65536 or position == stream.extent:
                    send.send(
                        (
                            "progress",
                            dict(
                                completed=position,
                                total=stream.extent,
                                message="Searching known stream bytes",
                            ),
                        )
                    )
                    last_progress = position

            result = search_known(
                chunks(), bytes.fromhex(pattern), start, 1000, cancel.is_set, progress
            )
        if cancel.is_set():
            raise WorkCancelled
        send.send(
            (
                "succeeded",
                dict(
                    stream_id=str(stream_id),
                    pattern_hex=pattern,
                    reconstruction_version=stream.reconstruction_version,
                    **result,
                ),
            )
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except StorageError as exc:
        send.send(("failed", str(exc)))
    except Exception:
        send.send(("failed", "Stream search failed; saved evidence remains usable"))
    finally:
        if engine:
            engine.dispose()
        send.close()
