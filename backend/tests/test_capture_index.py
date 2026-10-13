import json
import struct
from pathlib import Path
from uuid import UUID

import pytest

from protocol_lab.capture.index import CaptureError, IndexSettings, WorkCancelled, index_capture

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
CAPTURE_ID = UUID("12345678-1234-1234-1234-123456789abc")


def read(name, policy="warn"):
    return list(index_capture(FIXTURES / name, CAPTURE_ID, IndexSettings(checksum_policy=policy)))


def test_ordered_bytes_offsets_time_and_headers():
    expected = json.loads((FIXTURES / "expected.json").read_text())["ordered.pcap"]
    packets = read("ordered.pcap")
    raw = (FIXTURES / "ordered.pcap").read_bytes()
    for i, packet in enumerate(packets):
        assert packet.file_offset == expected["packet_offsets"][i]
        assert packet.payload_offset == expected["payload_offsets"][i]
        assert packet.timestamp_ns == expected["timestamp_ns"][i]
        start = packet.file_offset + packet.payload_offset
        assert raw[start : start + packet.payload_length].hex() == expected["payloads_hex"][i]
        assert packet.source_ip == "192.0.2.1"
        assert packet.destination_port == 9000
        assert packet.tcp_sequence == 100 + i * 5
        assert packet.ipv4_checksum == packet.tcp_checksum == "valid"
        assert packet.eligible_for_reassembly
        assert packet.diagnostics == ()
    assert [p.id for p in packets] == [p.id for p in read("ordered.pcap")]


def test_nano_big_endian():
    packet = read("big-endian-nano.pcap")[0]
    assert packet.timestamp_ns == 1700000000000000123
    assert packet.payload_length == 5


def test_pcapng_interfaces_sections_and_exact_resolution():
    packets = read("multi-interface.pcapng")
    assert len(packets) == 3
    assert [p.section_index for p in packets] == [0, 0, 1]
    assert [p.interface_id for p in packets] == [0, 1, 0]
    assert [p.timestamp_ns for p in packets] == [
        1700000000000123000,
        1700000002000000123,
        1700000000000124000,
    ]
    raw = (FIXTURES / "multi-interface.pcapng").read_bytes()
    for packet in packets:
        start = packet.file_offset + packet.payload_offset
        assert raw[start : start + packet.payload_length] == b"HELLO"
        assert packet.record_offset + 28 == packet.file_offset
        assert packet.tcp_checksum == "valid"


def test_simple_packet_does_not_invent_timestamp():
    packet = read("simple-packet.pcapng")[0]
    assert packet.timestamp_ns is None
    assert "timestamp_unavailable" in packet.diagnostics


def test_checksum_warn_ignore_reject_and_partial_packets():
    packets = read("mixed-diagnostics.pcap")
    assert len(packets) == 4
    good, bad, truncated, malformed = packets
    assert good.diagnostics == ()
    assert bad.tcp_checksum == "invalid"
    assert bad.eligible_for_reassembly
    assert "tcp_checksum_invalid" in bad.diagnostics
    assert truncated.payload_length == 3 and truncated.declared_payload_length == 5
    assert truncated.tcp_checksum == "unavailable"
    assert "capture_truncated" in truncated.diagnostics
    assert not malformed.eligible_for_reassembly
    assert "malformed_or_truncated_headers" in malformed.diagnostics
    rejected = read("mixed-diagnostics.pcap", "reject")[1]
    assert not rejected.eligible_for_reassembly
    assert rejected.payload_length == 5  # Index/source retained, no hidden discard.
    ignored = read("mixed-diagnostics.pcap", "ignore")[1]
    assert ignored.tcp_checksum == "unchecked"
    assert "tcp_checksum_invalid" not in ignored.diagnostics


def test_vlan_raw_and_unsupported_linktypes():
    assert read("vlan.pcap")[0].payload_offset == 58
    assert read("raw-ip.pcap")[0].payload_offset == 40
    unsupported = read("unsupported-link.pcap")[0]
    assert unsupported.diagnostics == ("unsupported_linktype",)
    assert unsupported.captured_length == 59


def test_corrupt_container_rejected_and_limits(tmp_path):
    path = tmp_path / "source"
    original = (FIXTURES / "ordered.pcap").read_bytes()
    for data in [
        original[:-1],
        original[:30],
        b"bad!",
        original[:24] + struct.pack("<IIII", 0, 0, 20_000_000, 20_000_000),
    ]:
        path.write_bytes(data)
        with pytest.raises(CaptureError):
            list(index_capture(path, CAPTURE_ID, IndexSettings()))
    with pytest.raises(CaptureError, match="max_packets"):
        list(index_capture(FIXTURES / "ordered.pcap", CAPTURE_ID, IndexSettings(max_packets=1)))
    ng = bytearray((FIXTURES / "multi-interface.pcapng").read_bytes())
    ng[-1] ^= 1
    path.write_bytes(ng)
    with pytest.raises(CaptureError):
        list(index_capture(path, CAPTURE_ID, IndexSettings()))


def test_cancel_before_reading_packet():
    with pytest.raises(WorkCancelled):
        list(index_capture(FIXTURES / "ordered.pcap", CAPTURE_ID, IndexSettings(), lambda: True))


def test_timestamp_json_preserves_nanoseconds():
    from protocol_lab.capture.index import IndexedPacket

    packet = read("big-endian-nano.pcap")[0]
    wire = json.loads(packet.model_dump_json())
    assert wire["timestamp_ns"] == "1700000000000000123"
    assert IndexedPacket.model_validate(wire).timestamp_ns == packet.timestamp_ns


def test_unsupported_network_fragments_and_incomplete_tcp_headers(tmp_path):
    from protocol_lab.capture.index import Frame, decode_frame

    raw = (FIXTURES / "ordered.pcap").read_bytes()[40:99]
    # Valid link layer, truncated IPv4 header must get malformed diagnostics.
    short = decode_frame(Frame(raw[:24], 0, 0, len(raw), 0, 1), CAPTURE_ID, 0, "warn")
    assert "malformed_or_truncated_headers" in short.diagnostics
    fragment = bytearray(raw)
    fragment[20:22] = b"\x20\x00"  # IPv4 MF bit.
    packet = decode_frame(Frame(bytes(fragment), 0, 0, len(raw), 0, 1), CAPTURE_ID, 0, "warn")
    assert "ipv4_fragmented_unsupported" in packet.diagnostics
    assert packet.source_ip == "192.0.2.1"
    assert not packet.eligible_for_reassembly
    short_tcp = decode_frame(Frame(raw[:45], 0, 0, len(raw), 0, 1), CAPTURE_ID, 0, "warn")
    assert "malformed_or_truncated_headers" in short_tcp.diagnostics
    assert short_tcp.payload_offset is None
    ip_bad = bytearray(raw)
    ip_bad[24] ^= 1  # Change TTL without recalculating checksum.
    checksum_bad = decode_frame(Frame(bytes(ip_bad), 0, 0, len(raw), 0, 1), CAPTURE_ID, 0, "warn")
    assert checksum_bad.ipv4_checksum == "invalid"
    assert checksum_bad.eligible_for_reassembly


def test_binary_pcapng_resolution_and_legacy_packet_block(tmp_path):
    import dpkt

    packet = (FIXTURES / "ordered.pcap").read_bytes()[40:99]
    option = dpkt.pcapng.PcapngOptionLE(code=9, data=b"\x8a")  # 2^-10 seconds
    idb = dpkt.pcapng.InterfaceDescriptionBlockLE(opts=[option, dpkt.pcapng.PcapngOptionLE(code=0)])
    legacy = dpkt.pcapng.PacketBlockLE(ts_low=1025, pkt_data=packet)
    path = tmp_path / "legacy.pcapng"
    path.write_bytes(bytes(dpkt.pcapng.SectionHeaderBlockLE()) + bytes(idb) + bytes(legacy))
    result = list(index_capture(path, CAPTURE_ID, IndexSettings()))[0]
    assert result.timestamp_ns == 1000976562
    assert "timestamp_rounded_to_ns" in result.diagnostics
    assert result.payload_length == 5


def test_unindexed_pcapng_block_is_reported_without_losing_packets(tmp_path):
    path = tmp_path / "custom.pcapng"
    original = (FIXTURES / "multi-interface.pcapng").read_bytes()
    # Final section is big endian; append a well-formed block with an unknown type.
    path.write_bytes(original + struct.pack(">III", 12345, 12, 12))
    warnings = []
    packets = list(
        index_capture(
            path,
            CAPTURE_ID,
            IndexSettings(),
            container_warning=lambda kind, offset: warnings.append((kind, offset)),
        )
    )
    assert len(packets) == 3
    assert warnings == [(12345, len(original))]


def test_unsupported_nested_ethernet_does_not_recursively_decode_or_block_neighbors(tmp_path):
    import struct

    from protocol_lab.capture.index import Frame, decode_frame

    nested = (b"\0" * 12 + struct.pack("!H", 0x6558)) * 600
    frame = Frame(
        data=nested,
        record_offset=24,
        file_offset=40,
        original_length=len(nested),
        timestamp_ns=1,
        linktype=1,
    )
    result = decode_frame(frame, CAPTURE_ID, 0, "warn")
    assert result.diagnostics == ("unsupported_network_protocol",)
    assert not result.eligible_for_reassembly

    # Real index iteration must continue to good neighboring packets.
    good_source = (FIXTURES / "ordered.pcap").read_bytes()
    good_record = good_source[24:99]
    path = tmp_path / "nested.pcap"
    path.write_bytes(
        good_source[:24]
        + struct.pack("<IIII", 1, 0, len(nested), len(nested))
        + nested
        + good_record
    )
    packets = list(index_capture(path, CAPTURE_ID, IndexSettings()))
    assert len(packets) == 2
    assert packets[1].eligible_for_reassembly
