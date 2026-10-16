"""Deterministic synthetic A1 protocol bytes; independent TCP segmentation and values."""

from pathlib import Path
import hashlib
import io
import json
import zlib

import dpkt

from generate_framing_fixtures import capture

ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/inference"


def messages(sizes, endian="little"):
    return b"".join(b"\xaa\xbb"+n.to_bytes(2, endian)+bytes([65+i])*n
                    for i, n in enumerate(sizes))


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    for name, data, cuts in [
        ("length-discovery", messages([3, 7, 4, 9, 5, 11]), [1, 5, 21]),
        ("length-holdout", messages([13, 8, 17, 6]), [3, 26]),
        ("length-counterexample", messages([15, 6, 12])+b"\xaa\xbb\x00\x00?", [2, 19]),
        ("fixed-markers", b"".join(b"\xaa\xbb"+bytes([65+i])*4+b"\xcc\xdd" for i in range(8)), [7, 10, 27]),
        ("big-endian", messages([3, 7, 4, 9, 5, 11], "big"), [1, 5, 21]),
    ]:
        (ROOT / f"{name}.pcap").write_bytes(capture(data, cuts))
    def crc_messages(sizes, corrupt=False):
        records = []
        for index, size in enumerate(sizes):
            payload = hashlib.shake_256(f"a4:{index}:{size}".encode()).digest(size)
            body = b"\xaa\xbb" + (size + 9).to_bytes(2, "little") + bytes([index]) + payload
            checksum = zlib.crc32(body) & 0xFFFFFFFF
            if corrupt and index == len(sizes) - 1:
                checksum ^= 1
            records.append(body + checksum.to_bytes(4, "little"))
        return b"".join(records)

    for name, sizes, cuts, corrupt in [
        ("crc-discovery", [3, 7, 4, 9, 5, 11], [1, 5, 21], False),
        ("crc-holdout", [13, 8, 17, 6], [3, 26], False),
        ("crc-counterexample", [15, 6, 12, 10], [2, 19], True),
        ("crc-resegmented", [3, 7, 4, 9, 5, 11], [4, 16, 37, 61], False),
    ]:
        data = crc_messages(sizes, corrupt)
        encoded = capture(data, cuts)
        (ROOT / f"{name}.pcap").write_bytes(encoded)
        if name == "crc-holdout":
            output = io.BytesIO()
            writer = dpkt.pcapng.Writer(output)
            for timestamp, packet in dpkt.pcap.Reader(io.BytesIO(encoded)):
                writer.writepkt(packet, timestamp)
            (ROOT / f"{name}.pcapng").write_bytes(output.getvalue())
    model = dict(
        schema_version="interpretation-2", name="A4 reproducible CRC32 and counter",
        framing=dict(rule=dict(kind="length", offset=2, width=2, endian="little", adjustment=0)),
        fields=[dict(kind="bytes", name="magic", length=2, constant_hex="aabb"),
                dict(kind="int", name="length", width=2, endian="little", signed=False),
                dict(kind="int", name="counter", width=1, endian="big", signed=False),
                dict(kind="bytes", name="payload", length=dict(remaining_minus=4)),
                dict(kind="int", name="crc", width=4, endian="little", signed=False)],
        checks=[dict(kind="length", field="payload", expected=dict(field="length", add=-9)),
                dict(kind="checksum", field="crc", algorithm="CRC-32/ISO-HDLC",
                     byte_order="little", coverage="before_field")],
        corpus_checks=[dict(kind="counter", name="sequence", field="counter")],
    )
    (ROOT / "a4-model.json").write_text(json.dumps(model, indent=2) + "\n")


if __name__ == "__main__":
    main()
