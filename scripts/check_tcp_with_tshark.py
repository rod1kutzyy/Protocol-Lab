"""Independent network header/payload check with local TShark; never live capture."""

import argparse
import json
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from protocol_lab.capture.index import IndexSettings, index_capture

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.cap_len",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.flags",
    "tcp.len",
    "tcp.payload",
]


def check(path, binary):
    completed = subprocess.run(
        [
            binary,
            "-n",
            "-r",
            str(path),
            "-T",
            "fields",
            "-E",
            "occurrence=f",
            *[argument for field in FIELDS for argument in ("-e", field)],
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    rows = completed.stdout.splitlines()
    packets = list(index_capture(path, UUID(int=1), IndexSettings()))
    assert len(rows) == len(packets), (path.name, "packet count")
    with path.open("rb") as source:
        for row, packet in zip(rows, packets, strict=True):
            values = dict(zip(FIELDS, row.split("\t"), strict=True))
            expected = {
                "frame.number": packet.index + 1,
                "frame.cap_len": packet.captured_length,
                "frame.len": packet.original_length,
                "ip.src": packet.source_ip,
                "ip.dst": packet.destination_ip,
                "tcp.srcport": packet.source_port,
                "tcp.dstport": packet.destination_port,
                "tcp.seq_raw": packet.tcp_sequence,
                "tcp.ack_raw": packet.tcp_acknowledgment,
                "tcp.flags": packet.tcp_flags,
                "tcp.len": packet.declared_payload_length,
            }
            for field, value in expected.items():
                actual = values[field]
                if value is None:
                    assert actual == "", (path.name, packet.index, field, actual, value)
                elif isinstance(value, int):
                    assert int(actual, 16 if field == "tcp.flags" else 10) == value, (
                        path.name,
                        packet.index,
                        field,
                        actual,
                        value,
                    )
                else:
                    assert actual == value, (
                        path.name,
                        packet.index,
                        field,
                        actual,
                        value,
                    )
            if packet.timestamp_ns is not None:
                assert (
                    int(Decimal(values["frame.time_epoch"]) * 1_000_000_000)
                    == packet.timestamp_ns
                )
            if packet.payload_length and packet.ip_protocol == 6:
                source.seek(packet.file_offset + packet.payload_offset)
                payload = source.read(packet.payload_length)
                assert values["tcp.payload"].replace(":", "") == payload.hex(), (
                    path.name,
                    packet.index,
                    "original payload/source offsets",
                )
    return len(packets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = shutil.which("tshark")
    if not binary:
        raise SystemExit("TShark unavailable; independent check was not performed")
    paths = sorted(
        [
            *ROOT.glob("tcp/*.pcap"),
            *ROOT.glob("framing/*.pcap"),
            *ROOT.glob("interpretation/*.pcap"),
            *[
                ROOT / n
                for n in [
                    "ordered.pcap",
                    "big-endian-nano.pcap",
                    "raw-ip.pcap",
                    "vlan.pcap",
                    "multi-interface.pcapng",
                ]
            ],
        ]
    )
    results = [
        {"fixture": str(path.relative_to(ROOT)), "packets": check(path, binary)}
        for path in paths
    ]
    report = {
        "tshark": subprocess.check_output(
            [binary, "--version"], text=True
        ).splitlines()[0],
        "fields": FIELDS,
        "fixtures": results,
        "packets": sum(r["packets"] for r in results),
        "excluded": [
            "unsupported linktype: no applicable independent decoder",
            "simple-packet.pcapng: no source timestamp in Simple Packet Block",
            "mixed-diagnostics.pcap: malformed headers have decoder-specific diagnostics",
        ],
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
