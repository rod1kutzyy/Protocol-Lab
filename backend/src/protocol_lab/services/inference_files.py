"""File adapter for the shared inference engine. No PostgreSQL/network is required."""

import hashlib
import json
from bisect import bisect_right
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from protocol_lab import __version__
from protocol_lab.capture.index import IndexSettings, index_capture, sha256_file
from protocol_lab.domain.models import ByteRange, SourceRange
from protocol_lab.framing.source import stream_input
from protocol_lab.inference.document import load_document
from protocol_lab.inference.engine import StreamData, discover, evaluate
from protocol_lab.inference.models import (
    CandidateInput,
    InferenceSnapshot,
    InferenceSpec,
)
from protocol_lab.services.application import sum_status
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.storage.inference import versions
from protocol_lab.tcp.reassembly import VERSION as TCP_VERSION
from protocol_lab.tcp.reassembly import ReconstructionSettings, reconstruct
from protocol_lab.validation.models import CaptureSnapshot, StoredCorpus, StreamSnapshot


def infer_files(paths, document, output, holdout_paths=(), candidate_document=None, settings=None):
    settings = settings or IndexSettings()
    original = None
    candidate = load_document(candidate_document, "candidate") if candidate_document else None
    if document and json.loads(document).get("schema_version") == "inference-snapshot-1":
        original = load_document(document, "snapshot")
        spec = original.spec
    elif document:
        spec = load_document(document)
    else:
        spec = None
    path_hashes = {Path(path): sha256_file(Path(path)) for path in [*paths, *holdout_paths]}
    if len(set(path_hashes.values())) != len(path_hashes):
        raise ValueError("Duplicate original captures are not independent file inputs")
    expected = {c.sha256: c for c in original.sources} if original else {}
    if original and set(expected) != set(path_hashes.values()):
        raise ValueError("Supply every exact capture frozen in the snapshot, by SHA-256")
    sources, inputs, reconstructions = [], [], []
    with ExitStack() as stack:
        for path, checksum in sorted(path_hashes.items(), key=lambda pair: pair[1]):
            frozen = expected.get(checksum)
            capture_id = (
                frozen.id if frozen else uuid5(NAMESPACE_URL, f"protocol-lab:capture:{checksum}")
            )
            capture_settings = (
                IndexSettings.model_validate(frozen.import_settings) if frozen else settings
            )
            packets = list(index_capture(path, capture_id, capture_settings))
            packet_times = {
                packet.id: packet.timestamp_ns
                for packet in packets
                if packet.timestamp_ns is not None
            }
            file = stack.enter_context(path.open("rb"))

            def payload(packet, file=file):
                file.seek(packet.file_offset + packet.payload_offset)
                return file.read(packet.payload_length)

            reconstruction = reconstruct(
                capture_id,
                packets,
                payload,
                ReconstructionSettings.model_validate(frozen.reconstruction_settings or {})
                if frozen
                else ReconstructionSettings(),
            )
            reconstructed_sha = hashlib.sha256(
                reconstruction.model_dump_json().encode()
            ).hexdigest()
            if frozen and (
                frozen.reconstruction_engine_version != TCP_VERSION
                or frozen.reconstruction_sha256
                and frozen.reconstruction_sha256 != reconstructed_sha
            ):
                raise ValueError("Frozen reconstruction cannot be reproduced by this engine")
            actual = {s.id: s for session in reconstruction.sessions for s in session.streams}
            streams = tuple(
                StreamSnapshot(
                    id=s.id,
                    session_id=s.session_id,
                    reconstruction_version=s.reconstruction_version,
                    reconstruction_policy=s.reconstruction_policy,
                    extent=s.extent,
                    direction=s.direction,
                    included=True,
                    data_status_bytes=dict(sum_status(s)),
                )
                for s in sorted(actual.values(), key=lambda s: str(s.id))
            )
            if frozen:
                if {s.id for s in frozen.streams} != set(actual):
                    raise ValueError("Frozen stream identities differ")
                for s in frozen.streams:
                    if actual[s.id].extent != s.extent:
                        raise ValueError("Frozen stream extent differs")
                capture = frozen
            else:
                capture = CaptureSnapshot(
                    id=capture_id,
                    sha256=checksum,
                    size_bytes=path.stat().st_size,
                    packet_count=len(packets),
                    eligible_packets=sum(p.eligible_for_reassembly for p in packets),
                    checksum_policy=capture_settings.checksum_policy,
                    import_settings=capture_settings.model_dump(),
                    import_engine_version=__version__,
                    diagnostics={},
                    reconstruction_id=uuid5(capture_id, TCP_VERSION),
                    reconstruction_sha256=reconstructed_sha,
                    reconstruction_settings=reconstruction.settings.model_dump(),
                    reconstruction_engine_version=TCP_VERSION,
                    streams=streams,
                )
            sources.append(capture)
            for s in capture.streams:
                actual_stream = actual[s.id]

                def provenance(
                    a,
                    spans=actual_stream.spans,
                    ends=tuple(span.byte_range.end for span in actual_stream.spans),
                ):
                    records = []
                    for index in range(bisect_right(ends, a.byte_range.start), len(spans)):
                        span = spans[index]
                        if span.byte_range.start >= a.byte_range.end:
                            break
                        left, right = (
                            max(a.byte_range.start, span.byte_range.start),
                            min(a.byte_range.end, span.byte_range.end),
                        )
                        if left >= right:
                            continue
                        for source in span.sources:
                            shift = left - span.byte_range.start
                            records.append(
                                SourceRange(
                                    capture_id=source.capture_id,
                                    packet_id=source.packet_id,
                                    packet_payload_range=ByteRange(
                                        start=source.packet_payload_range.start + shift,
                                        end=source.packet_payload_range.start
                                        + shift
                                        + right
                                        - left,
                                    ),
                                    stream=a.model_copy(
                                        update={"byte_range": ByteRange(start=left, end=right)}
                                    ),
                                )
                            )
                    return tuple(records)

                stream_data = StreamData(
                    capture,
                    s,
                    stream_input(actual_stream, actual_stream.spans, file),
                    provenance,
                )
                stream_data.packet_times = tuple(
                    (span.byte_range.start, span.byte_range.end, packet_times[source.packet_id])
                    for span in actual_stream.spans
                    for source in span.sources
                    if source.packet_id in packet_times
                )
                inputs.append(stream_data)
            reconstructions.append(reconstruction)
        if spec is None:
            if candidate is None:
                raise ValueError("Provide a versioned inference specification")
            spec = InferenceSpec.model_validate(
                dict(
                    corpus_version_id=uuid5(candidate.run_id, "file-evaluation-corpus"),
                    mode="evaluate",
                    candidate_ids=[candidate.id],
                    detectors=[dict(family="framing")],
                    split=dict(
                        discovery_ids=[c.id for c in sources],
                        holdout_unavailable_reason="New fixed-rule CLI evaluation",
                    ),
                )
            )
        if original:
            snapshot = original.model_copy(update={"sample_anchors": ()})
        else:
            project = uuid5(spec.corpus_version_id, "file-project")
            corpus = StoredCorpus(
                id=spec.corpus_version_id,
                corpus_id=uuid5(project, "file-corpus"),
                project_id=project,
                name="CLI capture corpus",
                spec=dict(capture_ids=[c.id for c in sources]),
                sha256=hashlib.sha256(spec.model_dump_json().encode()).hexdigest(),
                created_at=datetime.now(UTC),
            )
            snapshot = InferenceSnapshot(
                project_id=project,
                spec=spec,
                corpus=corpus,
                sources=tuple(sorted(sources, key=lambda c: str(c.id))),
                candidates=()
                if candidate is None
                else (
                    CandidateInput(
                        id=candidate.id, sha256=candidate.rule_sha256, rule=candidate.rule
                    ),
                ),
                engines=versions(),
            )
        if candidate:
            result, evidence = evaluate(
                snapshot,
                candidate,
                inputs,
                candidate.run_id,
                independence="unverified",
                reason=(
                    "File-based evaluation; prior exposure is not tracked without project history"
                ),
            )
            candidates = []
        else:
            result, candidates, evidence = discover(snapshot, inputs)
        # Detect concurrent mutation before publication.
        if any(sha256_file(path) != checksum for path, checksum in path_hashes.items()):
            raise ValueError("Capture changed during inference; no output published")
        budget = ResultBudget(ResultLimits(max_bytes=spec.budget.max_evidence_bytes))

        def write(value):
            text = json.dumps(value, separators=(",", ":"))
            budget.consume(text)
            output.write(text)

        output.write('{"format":"protocol-lab-inference","format_version":1,"result":')
        write(result.model_dump(mode="json"))
        for name, records in (
            ("candidates", candidates),
            ("evidence", evidence),
            ("provenance", reconstructions),
        ):
            output.write(',"' + name + '":[')
            for index, value in enumerate(records):
                if index:
                    output.write(",")
                write(value.model_dump(mode="json"))
            output.write("]")
        output.write("}\n")
        return result
