"""Length-prefixed messages with count-based arrays and two payload variants."""

from pathlib import Path

from generate_framing_fixtures import capture

ROOT = Path(__file__).resolve().parents[1] / "tests/fixtures/interpretation"


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    messages = [b"\x02\x01\xfe\xff\x02AB", b"\x01\x01\x34\x12", b"\x00"]
    data = b"".join(len(body).to_bytes(2, "big") + body for body in messages)
    (ROOT / "arrays-variants.pcap").write_bytes(capture(data, [1, 5, 12]))
    new = b"\x01\x02CD"
    (ROOT / "arrays-new-parameters.pcap").write_bytes(
        capture(len(new).to_bytes(2, "big") + new, [3])
    )


if __name__ == "__main__":
    main()
