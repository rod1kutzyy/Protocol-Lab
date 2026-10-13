"""Synthetic framing captures: variable lengths, split headers and explicit markers."""

from pathlib import Path

from generate_capture_fixtures import pcap
from generate_tcp_fixtures import handshake, packet

ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/framing"


def capture(data, cuts):
    packets = handshake()
    cursor = 0
    for end in [*cuts, len(data)]:
        packets.append(packet(100 + cursor, data[cursor:end]))
        cursor = end
    return pcap(packets)


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for endian in ["big", "little"]:
        data = b"".join(
            len(payload).to_bytes(2, endian) + payload
            for payload in [b"ABC", b"DEFGH", b"Z"]
        )
        (ROOT / f"length-{endian}.pcap").write_bytes(capture(data, [1, 9]))
    (ROOT / "markers.pcap").write_bytes(
        capture(b"noise\xaa\xbbABC\xcc\xdd\xaa\xbbDEFGH\xcc\xddtail", [6, 11])
    )
    (ROOT / "length-incomplete.pcap").write_bytes(
        capture(b"\x00\x03ABC\xff\xff?", [1, 6])
    )


if __name__ == "__main__":
    main()
