"""Native bounded checksum analysis file-adapter measurement; PostgreSQL/UI/concurrency are excluded."""

import argparse
import ctypes
import hashlib
import json
import platform
import tempfile
import time
import zlib
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from generate_framing_fixtures import capture
from protocol_lab.capture.index import sha256_file
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.models import InferenceCandidate
from protocol_lab.interpretation.document import load_model
from protocol_lab.services.application import apply_capture
from protocol_lab.services.inference_files import infer_files


def peak_rss_bytes():
    if platform.system() != "Windows":
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if platform.system() == "Darwin" else peak * 1024

    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [
            (name, ctypes.c_size_t)
            for name in (
                "peak_working_set",
                "working_set",
                "peak_paged",
                "paged",
                "peak_nonpaged",
                "nonpaged",
                "pagefile",
                "peak_pagefile",
            )
        ]

    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    if not psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
    return counters.peak_working_set


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 10 <= args.messages <= 100000:
        parser.error("messages must be 10..100000")
    messages = []
    for index in range(args.messages):
        size = 3 + index % 117
        body = b"\xaa\xbb" + (size + 9).to_bytes(2, "little") + bytes([index % 256])
        body += hashlib.shake_256(str(index).encode()).digest(size)
        messages.append(body + zlib.crc32(body).to_bytes(4, "little"))
    data = b"".join(messages)
    phases = {}
    with tempfile.TemporaryDirectory(prefix="protocol-lab-checksums-") as temporary:
        root = Path(temporary)
        source = root / "source.pcap"
        source.write_bytes(capture(data, list(range(1400, len(data), 1400))))
        capture_id = uuid5(NAMESPACE_URL, f"protocol-lab:capture:{sha256_file(source)}")
        spec = {
            "corpus_version_id": str(uuid5(capture_id, "checksums-benchmark")),
            "detectors": [{"family": "framing"}, {"family": "checksums"}],
            "split": {
                "discovery_ids": [str(capture_id)],
                "holdout_unavailable_reason": "Measurement only",
            },
            "budget": {
                "max_header_bytes": 8,
                "max_rule_trials": 5000,
                "max_checksum_operations": 1000000,
            },
            "search": {
                "fixed_size_max": 256,
                "adjustment_min": -8,
                "adjustment_max": 8,
                "marker_max_bytes": 4,
                "max_marker_patterns": 8,
            },
        }
        started = time.perf_counter()
        output = root / "discovery.json"
        with output.open("x") as file:
            run = infer_files([source], json.dumps(spec), file)
        phases["discovery_with_index_and_tcp_seconds"] = time.perf_counter() - started
        candidates = [
            InferenceCandidate.model_validate(value)
            for value in json.loads(output.read_text())["candidates"]
            if value["family"] == "checksums"
        ]
        candidate = next(
            (
                value
                for value in candidates[:5]
                if value.rule.algorithm == "CRC-32/ISO-HDLC"
                and value.rule.field_relative_to == "message_end"
                and value.rule.field.endian == "little"
            ),
            None,
        )
        if candidate is None:
            raise SystemExit(
                "CRC32 was not retained in first five; inspect the declared budgets"
            )
        started = time.perf_counter()
        with (root / "evaluation.json").open("x") as file:
            evaluated = infer_files(
                [source], None, file, candidate_document=candidate.model_dump_json()
            )
        phases["fixed_evaluation_with_index_and_tcp_seconds"] = (
            time.perf_counter() - started
        )
        started = time.perf_counter()
        with (root / "apply.json").open("x") as file:
            counts = apply_capture(
                load_model(model_draft(candidate).document_json), source, file
            )
        phases["compiled_model_with_index_and_tcp_seconds"] = (
            time.perf_counter() - started
        )
        result = {
            "profile": "Native bounded checksum analysis file adapter; not the Linux control workload",
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "messages": args.messages,
            "packets": run.snapshot.sources[0].packet_count,
            "stream_bytes": len(data),
            "capture_bytes": source.stat().st_size,
            "phase_seconds": {key: round(value, 6) for key, value in phases.items()},
            "process_cumulative_peak_rss_bytes": peak_rss_bytes(),
            "memory_scope": "One process across all three phases; excludes DB/browser and concurrency",
            "spec": spec,
            "rule_trials": run.rule_trials,
            "search_complete": run.search_complete,
            "candidate_count": run.candidate_count,
            "correct_crc_in_first_five": True,
            "fixed_evaluation_metrics": evaluated.evaluation.metrics.model_dump(
                mode="json"
            ),
            "compiled_model_counts": counts.message_counts,
            "output_bytes": output.stat().st_size,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
