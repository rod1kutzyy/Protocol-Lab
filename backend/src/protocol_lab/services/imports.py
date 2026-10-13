"""Capture indexing worker and publication orchestration, shared by adapters."""

import os
from collections import Counter
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any
from uuid import UUID

from protocol_lab.capture.index import CaptureError, IndexSettings, WorkCancelled, index_capture


def import_worker(
    send: Connection,
    cancel: Any,
    source: str,
    index: str,
    capture_id: UUID,
    settings: IndexSettings,
):
    try:
        diagnostics = Counter()
        count = 0

        def progress(done, total):
            send.send(
                (
                    "progress",
                    {"completed": done, "total": total, "message": "Indexing source packets"},
                )
            )

        def container_warning(kind, _offset):
            code = f"unindexed_pcapng_block_type_{kind}"
            # Bound distinct keys even for adversarial custom block types.
            diagnostics[
                code
                if code in diagnostics or len(diagnostics) < 64
                else "additional_unindexed_block_types"
            ] += 1

        with Path(index).open("x") as output:
            for packet in index_capture(
                Path(source), capture_id, settings, cancel.is_set, progress, container_warning
            ):
                output.write(packet.model_dump_json() + "\n")
                diagnostics.update(packet.diagnostics)
                count += 1
            output.flush()
            os.fsync(output.fileno())
        if cancel.is_set():
            raise WorkCancelled
        send.send(("prepared", {"packet_count": count, "diagnostics": dict(diagnostics)}))
    except WorkCancelled:
        send.send(("cancelled", None))
    except CaptureError as exc:
        send.send(("failed", str(exc)))
    except Exception:
        send.send(("failed", "Capture indexing failed; no completed capture published"))
    finally:
        send.close()
