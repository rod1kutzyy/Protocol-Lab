"""Deterministic IPv4/TCP fixtures; regeneration requires backend dependencies."""

import json
from pathlib import Path

import dpkt
from generate_capture_fixtures import pcap

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "tcp"


def packet(seq, data=b"", flags=16, reverse=False, port=41000, ack=1):
    a, b = b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02"
    tcp = dpkt.tcp.TCP(
        sport=9000 if reverse else port,
        dport=port if reverse else 9000,
        seq=seq % (1 << 32),
        ack=ack,
        flags=flags,
        data=data,
    )
    ip = dpkt.ip.IP(
        src=b if reverse else a, dst=a if reverse else b, p=6, ttl=64, data=tcp
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x02\0\0\0\0\x01", dst=b"\x02\0\0\0\0\x02", type=0x0800, data=ip
        )
    )


def handshake(seq=99, server=499, port=41000):
    return [
        packet(seq, flags=2, port=port),
        packet(server, flags=18, reverse=True, port=port, ack=seq + 1),
        packet(seq + 1, port=port, ack=server + 1),
    ]


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    truncated = packet(108, b"IJKLM")
    fixtures = {
        "ordered.pcap": handshake()
        + [packet(100, b"HELLOWORLD"), packet(500, b"OK", reverse=True)],
        "reordered-retransmitted.pcap": handshake()
        + [
            packet(105, b"WORLD"),
            packet(100, b"HELLO"),
            packet(100, b"HELLO"),
            packet(103, b"LOWOR"),
        ],
        "gaps-overlaps.pcap": handshake()
        + [
            packet(100, b"ABCDE"),
            packet(102, b"CXE"),
            (truncated[:-3], len(truncated)),
        ],
        "wrap-fin.pcap": [
            packet(0xFFFFFFFD, b"AB", flags=2),
            packet(0, b"CD"),
            packet(2, flags=17),
            packet(700, flags=17, reverse=True),
            packet(3),
        ],
        "reused-tuple.pcap": handshake()
        + [
            packet(100, b"OLD"),
            packet(103, flags=17),
            packet(500, flags=17, reverse=True),
            packet(104),
        ]
        + handshake(999, 1499)
        + [packet(1000, b"NEW")],
        "syn-fin-retransmitted.pcap": handshake()[:1]
        + handshake()
        + [
            packet(100, b"ONE", flags=17),
            packet(100, b"ONE", flags=17),
            packet(500, flags=17, reverse=True),
            packet(104),
        ],
        "new-syn-without-close.pcap": handshake()
        + [packet(100, b"OLD")]
        + handshake(999, 1499)
        + [packet(1000, b"NEW")],
        "simultaneous-open.pcap": [
            packet(99, flags=2),
            packet(499, flags=2, reverse=True),
            packet(99, flags=18),
            packet(499, flags=18, reverse=True),
            packet(100, b"HELLO"),
        ],
        "missing-prefix.pcap": handshake() + [packet(105, b"WORLD")],
        "truncated-zero.pcap": handshake() + [(packet(100, b"HELLO")[:-5], 59)],
        "late-payload-after-fin.pcap": handshake()
        + [
            packet(105, flags=17),
            packet(500, flags=17, reverse=True),
            packet(100, b"HELLO"),
            packet(106),
        ],
        "conflicting-server-syn.pcap": handshake()
        + [packet(999, flags=18, reverse=True), packet(100, b"HELLO")],
        "midstream.pcap": [packet(105, b"WORLD"), packet(100, b"HELLO")],
        "isolated-ambiguous.pcap": handshake()
        + [
            packet(100, b"GOOD"),
            packet(0, b"X", port=42000),
            packet(1 << 31, b"Y", port=42000),
        ],
        "bad-checksum.pcap": [packet(100, b"ABC")[:-1] + b"X"],
        "delayed-syn.pcap": [
            packet(499, flags=18, reverse=True),
            packet(99, flags=2),
            packet(100, b"HELLO"),
        ],
    }
    for name, frames in fixtures.items():
        (ROOT / name).write_bytes(pcap(frames))
    (ROOT / "expected.json").write_text(
        json.dumps(
            {
                "ordered.pcap": {"a_to_b": "HELLOWORLD", "b_to_a": "OK"},
                "reordered-retransmitted.pcap": {"a_to_b": "HELLOWORLD"},
                "gaps-overlaps.pcap": {
                    "known": [[0, 3], [4, 5], [8, 10]],
                    "ambiguous": [[3, 4]],
                    "gap": [[5, 8]],
                    "truncated": [[10, 13]],
                },
                "wrap-fin.pcap": {"a_to_b": "ABCD", "extent": 4},
                "reused-tuple.pcap": {"sessions": 2, "a_to_b": ["OLD", "NEW"]},
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
