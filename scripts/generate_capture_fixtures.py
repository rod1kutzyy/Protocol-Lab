"""Generate tiny synthetic traffic only. No personal or captured network data."""

import json
import struct
from pathlib import Path

import dpkt

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures"


def ethernet(payload=b"HELLO", seq=100, vlan=False):
    tcp = dpkt.tcp.TCP(
        sport=41000, dport=9000, seq=seq, ack=1, flags=dpkt.tcp.TH_ACK, data=payload
    )
    ip = dpkt.ip.IP(
        src=b"\xc0\x00\x02\x01", dst=b"\xc0\x00\x02\x02", p=6, ttl=64, data=tcp
    )
    ip.len = len(ip)
    packet = bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x02\x00\x00\x00\x00\x01",
            dst=b"\x02\x00\x00\x00\x00\x02",
            type=0x0800,
            data=ip,
        )
    )
    if vlan:
        packet = packet[:12] + struct.pack("!HHH", 0x8100, 7, 0x0800) + packet[14:]
    return packet


def pcap(packets, endian="<", nano=False, linktype=1):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    data = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype)
    for index, item in enumerate(packets):
        captured, original = item if isinstance(item, tuple) else (item, len(item))
        data += (
            struct.pack(
                endian + "IIII", 1700000000, index + 123, len(captured), original
            )
            + captured
        )
    return data


def block(kind, body, endian="<"):
    size = 12 + len(body)
    return (
        struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)
    )


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def interface(linktype=1, resol=6, offset=0, endian="<"):
    options = struct.pack(endian + "HH", 9, 1) + bytes([resol, 0, 0, 0])
    options += struct.pack(endian + "HHq", 14, 8, offset) + b"\0" * 4
    return block(1, struct.pack(endian + "HHI", linktype, 0, 65535) + options, endian)


def epb(packet, iface=0, ticks=1700000000000123, endian="<"):
    body = struct.pack(
        endian + "IIIII",
        iface,
        ticks >> 32,
        ticks & 0xFFFFFFFF,
        len(packet),
        len(packet),
    )
    body += packet + b"\0" * (-len(packet) % 4)
    return block(6, body, endian)


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    good = ethernet()
    bad = bytearray(good)
    bad[-1] ^= 1  # TCP checksum invalid; IPv4 checksum remains valid.
    truncated = (good[:-2], len(good))
    malformed = b"\0" * 12
    fixtures = {
        "ordered.pcap": pcap([good, ethernet(b"WORLD", 105)]),
        "big-endian-nano.pcap": pcap([good], ">", True),
        "mixed-diagnostics.pcap": pcap([good, bytes(bad), truncated, malformed]),
        "vlan.pcap": pcap([ethernet(vlan=True)]),
        "unsupported-link.pcap": pcap([good], linktype=999),
        "raw-ip.pcap": pcap([good[14:]], linktype=101),
        "multi-interface.pcapng": section()
        + interface()
        + interface(101, 9, 2)
        + epb(good)
        + epb(good[14:], 1, 1700000000000000123)
        + section(">")
        + interface(1, 6, 0, ">")
        + epb(good, 0, 1700000000000124, ">"),
        "simple-packet.pcapng": section()
        + interface()
        + block(3, struct.pack("<I", len(good)) + good + b"\0" * (-len(good) % 4)),
    }
    for name, data in fixtures.items():
        (ROOT / name).write_bytes(data)
    expected = {
        "ordered.pcap": {
            "packet_offsets": [40, 115],
            "payload_offsets": [54, 54],
            "payloads_hex": [b"HELLO".hex(), b"WORLD".hex()],
            "timestamp_ns": [1700000000000123000, 1700000000000124000],
        }
    }
    (ROOT / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")


if __name__ == "__main__":
    main()
