"""Offline capture application adapter. Uses the same reconstruction/validation as the GUI."""

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from protocol_lab import __version__
from protocol_lab.capture.index import IndexSettings, WorkCancelled, index_capture, sha256_file
from protocol_lab.framing.engine import VERSION as FRAMING_VERSION
from protocol_lab.framing.source import stream_input
from protocol_lab.interpretation.engine import VERSION as INTERPRETATION_VERSION
from protocol_lab.interpretation.schema import canonical, content_hash
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.tcp.reassembly import VERSION as TCP_VERSION
from protocol_lab.tcp.reassembly import ReconstructionSettings, reconstruct
from protocol_lab.validation.corpus import CorpusEvaluator, PacketTimeIndex
from protocol_lab.validation.engine import (
    CoverageCounter,
    capture_diagnostics,
    reconstruction_diagnostics,
    reconstruction_failures,
    validate_stream,
)
from protocol_lab.validation.models import (
    VERSION as VALIDATION_VERSION,
)
from protocol_lab.validation.models import (
    CaptureSnapshot,
    CorpusSpec,
    RunSnapshot,
    StoredCorpus,
    StreamSnapshot,
    ValidationRun,
)


def apply_capture(
    model,
    capture: Path,
    output,
    settings=None,
    capture_id=None,
    cancelled=lambda: False,
    limits=None,
    action_events=(),
    action_logs=(),
):
    settings = settings or IndexSettings()
    checksum = sha256_file(capture)
    capture_id = capture_id or uuid5(NAMESPACE_URL, f"protocol-lab:capture:{checksum}")
    diagnostics = Counter()

    def warning(kind, _offset):
        code = f"unindexed_pcapng_block_type_{kind}"
        diagnostics[
            code
            if code in diagnostics or len(diagnostics) < 64
            else "additional_unindexed_block_types"
        ] += 1

    packets = list(
        index_capture(capture, capture_id, settings, cancelled, container_warning=warning)
    )
    for packet in packets:
        diagnostics.update(packet.diagnostics)
    with capture.open("rb") as source:

        def payload(packet):
            source.seek(packet.file_offset + packet.payload_offset)
            return source.read(packet.payload_length)

        reconstruction = reconstruct(
            capture_id, packets, payload, ReconstructionSettings(), cancelled
        )
        streams = tuple(
            sorted(
                (
                    StreamSnapshot(
                        id=stream.id,
                        session_id=session.id,
                        reconstruction_version=stream.reconstruction_version,
                        reconstruction_policy=stream.reconstruction_policy,
                        extent=stream.extent,
                        direction=stream.direction,
                        included=True,
                        data_status_bytes=dict(sum_status(stream)),
                    )
                    for session in reconstruction.sessions
                    for stream in session.streams
                ),
                key=lambda s: str(s.id),
            )
        )
        source_snapshot = CaptureSnapshot(
            id=capture_id,
            sha256=checksum,
            size_bytes=capture.stat().st_size,
            packet_count=len(packets),
            eligible_packets=sum(p.eligible_for_reassembly for p in packets),
            checksum_policy=settings.checksum_policy,
            import_settings=settings.model_dump(),
            import_engine_version=__version__,
            diagnostics=dict(diagnostics),
            reconstruction_id=uuid5(capture_id, TCP_VERSION),
            reconstruction_sha256=None,
            reconstruction_settings=reconstruction.settings.model_dump(),
            reconstruction_engine_version=TCP_VERSION,
            streams=streams,
            reconstruction_failures=tuple(
                failure
                for session in reconstruction.sessions
                for failure in reconstruction_failures(session)
            ),
        )
        project_id = uuid5(capture_id, "cli-project")
        model_id = uuid5(project_id, "cli-model")
        now = datetime.now(UTC)
        corpus = StoredCorpus(
            id=uuid5(project_id, "cli-corpus-version"),
            corpus_id=uuid5(project_id, "cli-corpus"),
            project_id=project_id,
            name="CLI capture",
            spec=CorpusSpec(capture_ids=(capture_id,)),
            sha256=checksum,
            created_at=now,
        )
        snapshot = RunSnapshot(
            id=uuid5(capture_id, f"{VALIDATION_VERSION}:{content_hash(model)}"),
            project_id=project_id,
            created_at=now,
            corpus=corpus,
            interpretation_version_id=uuid5(model_id, content_hash(model)),
            model_id=model_id,
            model_sha256=content_hash(model),
            document_json=canonical(model),
            framing=model.framing,
            framing_engine_version=FRAMING_VERSION,
            interpretation_engine_version=INTERPRETATION_VERSION,
            sources=(source_snapshot,),
            action_events=action_events,
            action_logs=action_logs,
        )
        counter = CoverageCounter(snapshot)
        relations = CorpusEvaluator(model, snapshot.id, action_events, cancelled)
        packet_times = {
            packet.id: packet.timestamp_ns for packet in packets if packet.timestamp_ns is not None
        }
        active_times = PacketTimeIndex((), {})
        active_source = None
        output.write('{"format":"protocol-lab-validation","format_version":1,"results":[')
        first = True
        budget = ResultBudget(limits or ResultLimits())

        def write(item):
            nonlocal first
            if cancelled():
                raise WorkCancelled
            if not first:
                output.write(",")
            first = False
            line = item.model_dump_json()
            budget.consume(line + "\n")
            output.write(line)
            counter.add(item)
            relations.add(item, active_times.get(item.anchor), active_source)

        for item in capture_diagnostics(snapshot.id, source_snapshot):
            write(item)
        for item in reconstruction_diagnostics(snapshot.id, source_snapshot):
            write(item)
        actual = {s.id: s for session in reconstruction.sessions for s in session.streams}
        for stream in streams:
            rebuilt = actual[stream.id]
            active_times = PacketTimeIndex(rebuilt.spans, packet_times)
            active_source = stream_input(rebuilt, rebuilt.spans, source)
            for item in validate_stream(
                snapshot.id,
                source_snapshot,
                stream,
                active_source,
                model,
                cancelled,
            ):
                write(item)
        for item in relations.finish():
            write(item)
        if sha256_file(capture) != checksum:
            raise ValueError("Capture changed while applying model; no output published")
        output.write(
            '],"run":'
            + ValidationRun(snapshot=snapshot, coverage=counter.result()).model_dump_json()
        )
        # Spans retain all variants/retransmissions, packet IDs/indexes and exact offsets.
        output.write(',"provenance":' + reconstruction.model_dump_json() + "}\n")
        return counter.result()


def sum_status(stream):
    counts = Counter()
    for span in stream.spans:
        counts[span.status] += span.byte_range.end - span.byte_range.start
    return counts
