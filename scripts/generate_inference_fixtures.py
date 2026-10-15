"""Deterministic synthetic A1 protocol bytes; independent TCP segmentation and values."""

from pathlib import Path

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


if __name__ == "__main__":
    main()
