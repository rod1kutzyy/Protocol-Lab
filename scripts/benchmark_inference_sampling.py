"""A0 metadata-only baseline; does not measure packet decoding or future detectors."""

import argparse
import hashlib
import json
import platform
import resource
import sys
import time
from pathlib import Path
from uuid import UUID

from protocol_lab.domain.models import StreamRange
from protocol_lab.inference.models import InferenceSpec
from protocol_lab.inference.sampling import SampleUnit, select_sample
from protocol_lab.validation.models import CaptureSnapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--units", type=int, default=100000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.units <= 1000000:
        parser.error("units must be 1..1000000")
    sources = tuple(
        CaptureSnapshot(
            id=UUID(int=capture),
            sha256=hashlib.sha256(str(capture).encode()).hexdigest(),
            size_bytes=0,
            packet_count=0,
            eligible_packets=0,
            checksum_policy="warn",
            import_settings={},
            import_engine_version="synthetic-metadata",
            diagnostics={},
            reconstruction_id=UUID(int=capture + 100),
            reconstruction_sha256="1" * 64,
            reconstruction_settings={},
            reconstruction_engine_version="tcp-v1",
            streams=tuple(
                {
                    "id": UUID(int=capture * 10000 + stream),
                    "session_id": UUID(int=capture * 100 + stream // 2),
                    "reconstruction_version": "tcp-v1",
                    "reconstruction_policy": "retain-all-overlaps",
                    "extent": (args.units + 1) * 16,
                    "direction": "a_to_b" if stream % 2 == 0 else "b_to_a",
                    "included": True,
                }
                for stream in range(20)
            ),
        )
        for capture in (1, 2)
    )
    spec = InferenceSpec(
        corpus_version_id=UUID(int=3),
        detectors=[{"family": "framing"}],
        split={"discovery_ids": [sources[0].id], "holdout_ids": [sources[1].id]},
        budget={"max_sample_units": max(100000, args.units)},
    )
    started = time.perf_counter()
    units = []
    for i in range(args.units):
        source = sources[i % 2]
        stream = source.streams[(i // 2) % 20]
        units.append(
            SampleUnit(
                capture_id=source.id,
                session_id=stream.session_id,
                anchor=StreamRange(
                    stream_id=stream.id,
                    reconstruction_version="tcp-v1",
                    byte_range={"start": i * 16, "end": (i + 1) * 16},
                ),
                payload_sha256=hashlib.sha256(str(i).encode()).hexdigest(),
            )
        )
    prepared = time.perf_counter()
    first = select_sample(spec, sources, units)
    sampled = time.perf_counter()
    second = select_sample(spec, reversed(sources), reversed(units))
    repeated = time.perf_counter()
    if first != second:
        raise RuntimeError("Traversal-order determinism failed")
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    report = {
        "profile": "inference-a0-metadata-only",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "units": args.units,
        "captures": 2,
        "sessions": 20,
        "stream_directions": 40,
        "payload_files_read": 0,
        "metadata_preparation_seconds": round(prepared - started, 6),
        "sampling_seconds": round(sampled - prepared, 6),
        "repeat_seconds": round(repeated - sampled, 6),
        "peak_rss_mib": round(
            rss / (1024 * 1024 if sys.platform == "darwin" else 1024), 3
        ),
        "selected_unique_units": len(first.entries),
        "holdout_units": first.holdout_units,
        "unselected_unique_units": first.unselected_unique_units,
        "deterministic": True,
        "sample_sha256": first.sha256,
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
