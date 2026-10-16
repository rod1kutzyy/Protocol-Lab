"""Reproducible A1 PCAP → shared inference → JSON baseline, not the Linux workload SLA."""

import argparse
import hashlib
import json
import platform
import resource
import tempfile
import time
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from generate_framing_fixtures import capture
from protocol_lab.capture.index import sha256_file
from protocol_lab.services.inference_files import infer_files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=int, default=10000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 3 <= args.messages <= 100000:
        parser.error("messages: 3..100000")
    data = b"".join(
        b"\xaa\xbb"
        + (8 + i % 127).to_bytes(2, "little")
        + i.to_bytes(4, "little")
        + hashlib.shake_256(str(i).encode()).digest(4 + i % 127)
        for i in range(args.messages)
    )
    with tempfile.TemporaryDirectory(prefix="protocol-lab-a1-benchmark-") as temporary:
        directory = Path(temporary)
        path, output = directory / "capture.pcap", directory / "run.json"
        path.write_bytes(capture(data, list(range(1400, len(data), 1400))))
        capture_id = uuid5(NAMESPACE_URL, f"protocol-lab:capture:{sha256_file(path)}")
        spec = {
            "corpus_version_id": str(uuid5(capture_id, "benchmark-corpus")),
            "detectors": [
                {"family": "framing"},
                {"family": "structure"},
                {"family": "entropy"},
            ],
            "split": {
                "discovery_ids": [str(capture_id)],
                "holdout_unavailable_reason": "Measured discovery only",
            },
            "budget": {"max_header_bytes": 8, "max_rule_trials": 5000},
            "search": {
                "fixed_size_max": 256,
                "adjustment_min": -8,
                "adjustment_max": 8,
                "marker_max_bytes": 4,
                "max_marker_patterns": 8,
            },
        }
        started = time.perf_counter()
        with output.open("x") as file:
            result = infer_files([path], json.dumps(spec), file)
        elapsed = time.perf_counter() - started
        body = json.loads(output.read_text())
        lengths = [
            c for c in body["candidates"] if c["rule"]["kind"] == "length_framing"
        ]
        correct = any(
            c["rule"]["framing"]["rule"]["offset"] == 2
            and c["rule"]["framing"]["rule"]["width"] == 2
            and c["rule"]["framing"]["rule"]["endian"] == "little"
            and c["rule"]["framing"]["rule"]["adjustment"] == 4
            for c in lengths[:5]
        )
        record = {
            "profile": "A1 tuned local file adapter baseline; no PostgreSQL/browser/holdout",
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "messages": args.messages,
            "stream_bytes": len(data),
            "capture_bytes": path.stat().st_size,
            "elapsed_seconds": round(elapsed, 6),
            "peak_rss_mib": round(
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                / (1024**2 if platform.system() == "Darwin" else 1024),
                3,
            ),
            "output_bytes": output.stat().st_size,
            "candidate_count": result.candidate_count,
            "search_complete": result.search_complete,
            "trials": result.rule_trials,
            "correct_length_in_first_five": correct,
            "semantic_sha256": result.semantic_sha256,
            "spec": spec,
            "measured_stages": [
                "index",
                "TCP",
                "proposals",
                "shared framing",
                "regions/profile",
                "file publication",
            ],
        }
        if args.output:
            args.output.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record, indent=2))
        if not correct:
            raise SystemExit(
                "Expected length rule was not retained; inspect search budget/diagnostics"
            )


if __name__ == "__main__":
    main()
