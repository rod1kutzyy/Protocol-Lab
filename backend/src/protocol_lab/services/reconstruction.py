"""Cancellable local reconstruction process; core remains storage-independent."""

import os
from pathlib import Path

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.projects import ProjectStore, StorageError
from protocol_lab.storage.reconstruction import ReconstructionStore
from protocol_lab.tcp.reassembly import ReconstructionError, reconstruct


def reconstruction_worker(send, cancel, database_url, project_root, capture_id, artifact, settings):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(project_root))
        capture = projects.get_capture(capture_id)
        projects.get(capture.project_id)
        projects.verify_source(capture_id)
        repository = ReconstructionStore(projects)
        source_path = projects.safe_path(capture.project_id, capture.relative_path)

        def progress(done, total):
            send.send(
                (
                    "progress",
                    {
                        "completed": done,
                        "total": total,
                        "message": "Reconstructing TCP connections",
                    },
                )
            )

        with source_path.open("rb") as source:

            def payload(packet):
                source.seek(packet.file_offset + packet.payload_offset)
                return source.read(packet.payload_length)

            result = reconstruct(
                capture_id,
                repository.packet_records(capture_id),
                payload,
                settings,
                cancel.is_set,
                progress,
            )
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
                {
                    "session_count": len(result.sessions),
                    "excluded_packet_count": len(result.excluded_packet_ids),
                    "version": result.version,
                },
            )
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ReconstructionError) as exc:
        send.send(("failed", f"Capture {capture_id}: {exc}; previous results remain usable"))
    except Exception:
        send.send(
            ("failed", "TCP reconstruction failed; previous captures and results remain usable")
        )
    finally:
        if engine:
            engine.dispose()
        send.close()
