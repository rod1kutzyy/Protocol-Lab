"""Deterministic control workload. Fresh process per measurement; no research DB touched."""

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import struct
import subprocess
import sys
import time
from pathlib import Path
from uuid import UUID

import dpkt
from protocol_lab.capture.index import (
    IndexedPacket,
    IndexSettings,
    index_capture,
    sha256_file,
)
from protocol_lab.framing.engine import frame
from protocol_lab.framing.source import stream_input
from protocol_lab.interpretation.engine import compile_model, parse_message
from protocol_lab.interpretation.schema import ProtocolModel
from protocol_lab.services.application import apply_capture
from protocol_lab.tcp.reassembly import Reconstruction, reconstruct

CAPTURE_ID = UUID(int=10)
PROFILES = {"smoke": 2, "control": 1000}


def model():
    return ProtocolModel.model_validate(
        {
            "schema_version": "interpretation-1",
            "name": "Synthetic length-prefixed bytes",
            "framing": {"rule": {"kind": "length", "width": 4, "adjustment": 4}},
            "fields": [
                {
                    "kind": "int",
                    "name": "length",
                    "width": 4,
                    "signed": False,
                    "endian": "big",
                },
                {"kind": "bytes", "name": "payload", "length": {"field": "length"}},
            ],
        }
    )


def generate(path, connections):
    """250 packets and 100 messages per connection, one 65536-byte reply each."""
    index = 0
    with path.open("xb") as file:
        file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for connection in range(connections):
            count = 0
            port = 20000 + connection

            def packet(seq, data=b"", flags=16, reverse=False, ack=1, port=port):
                nonlocal index, count
                tcp = dpkt.tcp.TCP(
                    sport=9000 if reverse else port,
                    dport=port if reverse else 9000,
                    seq=seq,
                    ack=ack,
                    flags=flags,
                    data=data,
                )
                ip = dpkt.ip.IP(
                    src=b"\xc0\x00\x02\x02" if reverse else b"\xc0\x00\x02\x01",
                    dst=b"\xc0\x00\x02\x01" if reverse else b"\xc0\x00\x02\x02",
                    p=6,
                    ttl=64,
                    data=tcp,
                )
                ip.len = len(ip)
                raw = bytes(
                    dpkt.ethernet.Ethernet(
                        src=b"\x02\0\0\0\0\x01",
                        dst=b"\x02\0\0\0\0\x02",
                        type=0x0800,
                        data=ip,
                    )
                )
                file.write(
                    struct.pack(
                        "<IIII",
                        1700000000 + index // 1000000,
                        index % 1000000,
                        len(raw),
                        len(raw),
                    )
                )
                file.write(raw)
                index += 1
                count += 1

            packet(99, flags=2)
            packet(499, flags=18, reverse=True, ack=100)
            packet(100, ack=500)
            # Replies are in B -> A; framing ignores packet boundaries.
            data = b"".join(
                struct.pack(">I", length - 4) + bytes([n % 251]) * (length - 4)
                for n, length in enumerate([65536] + [180] * 99)
            )
            seq = 500
            for start in range(0, len(data), 1400):
                block = data[start : start + 1400]
                packet(seq, block, reverse=True, ack=100)
                seq += len(block)
            while count < 248:
                packet(100, ack=seq)
            packet(seq, flags=17, reverse=True, ack=100)
            packet(100, flags=17, ack=seq + 1)
    assert index == connections * 250
    assert path.stat().st_size <= 100 * 1024 * 1024
    return {
        "connections": connections,
        "packets": index,
        "messages": connections * 100,
        "capture_bytes": path.stat().st_size,
        "application_bytes": connections * 83356,
        "max_message_bytes": 65536,
        "sha256": sha256_file(path),
    }


class DigestOutput:
    """Record semantic reproducibility while retaining full output when requested."""

    def __init__(self, file=None):
        self.file = file
        self.digest = hashlib.sha256()
        self.bytes = 0

    def write(self, value):
        self.bytes += len(value.encode())
        # Only wall-clock creation timestamps vary. IDs, settings, coverage and provenance stay.
        normalized = re.sub(r'"created_at":"[^"]+"', '"created_at":"<run-time>"', value)
        self.digest.update(normalized.encode())
        if self.file:
            self.file.write(value)


def worker(operation, directory):
    capture = directory / "control.pcap"
    index = directory / "packets.jsonl"
    artifact = directory / "reconstruction.json"
    expected = json.loads((directory / "workload.json").read_text())
    start = time.perf_counter()
    details = {}
    if operation == "index":
        count = 0
        with index.open("x") as output:
            for p in index_capture(capture, CAPTURE_ID, IndexSettings()):
                assert p.eligible_for_reassembly and not p.diagnostics
                output.write(p.model_dump_json() + "\n")
                count += 1
        assert count == expected["packets"]
        details = {"packets": count, "artifact_bytes": index.stat().st_size}
    elif operation == "reconstruct":
        with index.open() as file, capture.open("rb") as source:

            def payload(p):
                source.seek(p.file_offset + p.payload_offset)
                return source.read(p.payload_length)

            result = reconstruct(
                CAPTURE_ID,
                (IndexedPacket.model_validate_json(l) for l in file),
                payload,
            )
        assert len(result.sessions) == expected["connections"]
        assert all(s.closed and not s.diagnostics for s in result.sessions)
        assert (
            sum(s.extent for c in result.sessions for s in c.streams)
            == expected["application_bytes"]
        )
        artifact.write_text(result.model_dump_json())
        details = {
            "sessions": len(result.sessions),
            "artifact_bytes": artifact.stat().st_size,
            "sha256": sha256_file(artifact),
        }
    elif operation in {"frame", "parse"}:
        result = Reconstruction.model_validate_json(artifact.read_bytes())
        document = model()
        parser = compile_model(document)
        count = total = largest = 0
        with capture.open("rb") as file:
            for c in result.sessions:
                for s in c.streams:
                    source = stream_input(s, s.spans, file)
                    framed = frame(
                        s.id,
                        s.reconstruction_version,
                        CAPTURE_ID,
                        expected["sha256"],
                        source,
                        document.framing,
                    )
                    for piece in framed.pieces:
                        assert piece.kind == "message" and piece.data_status == "known"
                        length = (
                            piece.anchor.byte_range.end - piece.anchor.byte_range.start
                        )
                        if operation == "parse":
                            parsed = parse_message(document, parser, piece, source)
                            assert (
                                parsed.status == "passed" and not parsed.unknown_ranges
                            )
                            assert int(parsed.fields[0].value) == length - 4
                        total += length
                        largest = max(largest, length)
                        count += 1
        assert count == expected["messages"] and total == expected["application_bytes"]
        assert largest == 65536
        details = {
            "messages": count,
            "application_bytes": total,
            "max_message_bytes": largest,
        }
    else:
        output = directory / "applied.json"
        with (
            output.open("x") if operation == "apply" else open(os.devnull, "w") as file
        ):
            sink = DigestOutput(file)
            coverage = apply_capture(model(), capture, sink, capture_id=CAPTURE_ID)
        assert coverage.message_counts["passed"] == expected["messages"]
        assert coverage.decoded_leaf_bytes == expected["application_bytes"]
        assert coverage.packets == expected["packets"]
        assert coverage.unframed_bytes == coverage.undecoded_bytes == 0
        details = {
            "coverage": coverage.model_dump(),
            "semantic_sha256": sink.digest.hexdigest(),
            "output_bytes": sink.bytes,
        }
    elapsed = time.perf_counter() - start
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux KiB, Darwin bytes. Includes loading preceding artifacts and all output serialization.
    peak_bytes = peak if sys.platform == "darwin" else peak * 1024
    return {
        "operation": operation,
        "seconds": round(elapsed, 3),
        "peak_rss_bytes": peak_bytes,
        **details,
    }


def read_limit(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, default="smoke")
    parser.add_argument(
        "--worker",
        choices=["index", "reconstruct", "frame", "parse", "apply", "repeat"],
    )
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker, args.output)))
        return
    args.output.mkdir(parents=True, exist_ok=True)
    workload = generate(args.output / "control.pcap", PROFILES[args.profile])
    (args.output / "workload.json").write_text(json.dumps(workload, indent=2))
    (args.output / "model.json").write_text(model().model_dump_json(indent=2))
    report = {
        "profile": args.profile,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "logical_cpus": os.cpu_count(),
        "cpu_max": read_limit("/sys/fs/cgroup/cpu.max"),
        "memory_max": read_limit("/sys/fs/cgroup/memory.max"),
        "workload": workload,
        "measurements": [],
        "measurement_scope": "core engines + artifact IO; no DB/HTTP",
    }
    for operation in ["index", "reconstruct", "frame", "parse", "apply", "repeat"]:
        completed = subprocess.run(
            [
                sys.executable,
                __file__,
                "--output",
                str(args.output),
                "--worker",
                operation,
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.returncode:
            report["failure"] = {
                "operation": operation,
                "exit_code": completed.returncode,
                "stderr": completed.stderr[-4000:],
            }
            (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))
            raise SystemExit(
                completed.stderr or f"{operation} failed: {completed.returncode}"
            )
        measurement = json.loads(completed.stdout)
        report["measurements"].append(measurement)
        print(json.dumps(measurement), flush=True)
        (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))
    report["reproducible"] = (
        report["measurements"][-1]["semantic_sha256"]
        == report["measurements"][-2]["semantic_sha256"]
    )
    assert report["reproducible"], (
        "Repeated execution changed facts, settings or provenance"
    )
    (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
