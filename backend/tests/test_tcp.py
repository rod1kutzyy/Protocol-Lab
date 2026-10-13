"""PCAP to stream tests check actual original bytes and exact provenance."""

import json
from pathlib import Path
from uuid import UUID

import pytest

from protocol_lab.capture.index import IndexSettings, WorkCancelled, index_capture
from protocol_lab.tcp.reassembly import Reconstruction, ReconstructionSettings, reconstruct

ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "tcp"
CAPTURE = UUID("86fb0000-0000-4000-8000-000000000001")
EXPECTED = json.loads((ROOT / "expected.json").read_text())


def load(name, settings=None, policy="warn", **kwargs):
    path = ROOT / name
    packets = list(index_capture(path, CAPTURE, IndexSettings(checksum_policy=policy)))
    raw = path.read_bytes()
    result = reconstruct(
        CAPTURE,
        packets,
        lambda p: raw[
            p.file_offset + p.payload_offset : p.file_offset + p.payload_offset + p.payload_length
        ],
        settings,
        **kwargs,
    )
    return result, raw, packets


def values(stream, raw):
    output = []
    for span in stream.spans:
        variants = {
            raw[e.file_offset : e.file_offset + span.byte_range.end - span.byte_range.start]
            for e in span.sources
        }
        for evidence in span.sources:
            assert evidence.stream.stream_id == stream.id
            assert evidence.stream.byte_range == span.byte_range
            assert (
                evidence.packet_payload_range.end - evidence.packet_payload_range.start
                == span.byte_range.end - span.byte_range.start
            )
        output.append((span.status, span.byte_range.start, span.byte_range.end, variants))
    return output


def known_bytes(stream, raw):
    return b"".join(next(iter(v)) for status, _, _, v in values(stream, raw) if status == "known")


def test_sparse_stream_distinguishes_truncation_from_gaps_at_each_boundary():
    _, raw, original = load("ordered.pcap")
    template = original[3]
    count = 4000
    packets = [
        template.model_copy(
            update={
                "id": UUID(int=i + 1),
                "index": i,
                "tcp_sequence": 100 + i * 3,
                "payload_length": 1,
                "declared_payload_length": 2,
            }
        )
        for i in range(count)
    ]
    result = reconstruct(CAPTURE, packets, lambda p: b"H")
    (stream, _) = result.sessions[0].streams
    assert stream.extent == count * 3 - 1
    assert len(stream.spans) == count * 3 - 1
    for i, span in enumerate(stream.spans):
        assert span.status == ("known", "truncated", "gap")[i % 3]
        assert (span.byte_range.start, span.byte_range.end) == (i, i + 1)
    assert known_bytes(stream, raw) == b"H" * count


def test_ordered_directions_and_multiple_messages_are_just_bytes():
    result, raw, packets = load("ordered.pcap")
    (session,) = result.sessions
    assert session.start_known and session.roles_known
    a, b = session.streams
    assert a.direction == "a_to_b" and b.direction == "b_to_a"
    assert known_bytes(a, raw) == EXPECTED["ordered.pcap"]["a_to_b"].encode()
    assert known_bytes(b, raw) == b"OK"
    assert a.extent == 10 and not a.issues
    (evidence,) = a.spans[0].sources
    assert evidence.packet_id == packets[3].id
    assert evidence.file_offset == packets[3].file_offset + 54
    assert evidence.packet_offset == 54
    assert evidence.packet_payload_range.start == 0
    assert Reconstruction.model_validate_json(result.model_dump_json()) == result


def test_reordering_duplicate_and_partial_retransmission_preserve_all_sources():
    result, raw, packets = load("reordered-retransmitted.pcap")
    a = result.sessions[0].streams[0]
    assert known_bytes(a, raw) == b"HELLOWORLD"
    assert a.extent == 10 and not a.issues
    assert len(a.spans[0].sources) == 2
    assert {e.packet_id for e in a.spans[0].sources} == {packets[4].id, packets[5].id}
    assert any(len(span.sources) == 3 for span in a.spans)
    for span in a.spans:
        for evidence in span.sources:
            packet = next(p for p in packets if p.id == evidence.packet_id)
            assert evidence.file_offset == packet.file_offset + evidence.packet_offset
            assert (
                evidence.packet_offset
                == packet.payload_offset + evidence.packet_payload_range.start
            )


def test_conflicts_gaps_and_truncation_never_invent_bytes():
    result, raw, _ = load("gaps-overlaps.pcap")
    stream = result.sessions[0].streams[0]
    rows = values(stream, raw)
    assert stream.extent == 13
    assert [(a, b, v) for status, a, b, v in rows if status == "ambiguous"] == [
        (3, 4, {b"D", b"X"})
    ]
    assert [(a, b, v) for status, a, b, v in rows if status == "gap"] == [(5, 8, set())]
    assert [(a, b, v) for status, a, b, v in rows if status == "truncated"] == [(10, 13, set())]
    assert len(stream.issues) == 3
    assert known_bytes(stream, raw) == b"ABCEIJ"


def test_wrap_syn_payload_fin_consumption_and_final_ack():
    result, raw, _ = load("wrap-fin.pcap")
    (session,) = result.sessions
    assert session.closed
    stream = session.streams[0]
    assert stream.extent == 4
    assert known_bytes(stream, raw) == b"ABCD"
    assert not stream.issues
    assert session.streams[1].extent == 0


def test_reused_tuple_has_distinct_instances_and_stable_ids():
    result, raw, _ = load("reused-tuple.pcap")
    assert len(result.sessions) == 2
    assert [known_bytes(s.streams[0], raw) for s in result.sessions] == [b"OLD", b"NEW"]
    assert len({s.id for s in result.sessions}) == 2
    assert result.sessions[0].closed and all(s.start_known for s in result.sessions)
    assert load("reused-tuple.pcap")[0] == result


def test_midstream_start_and_roles_unknown_origin_is_lowest_observed_byte():
    result, raw, _ = load("midstream.pcap")
    (session,) = result.sessions
    assert not session.start_known and not session.roles_known
    assert "connection_start_unavailable" in session.diagnostics
    assert known_bytes(session.streams[0], raw) == b"HELLOWORLD"


def test_ambiguous_sequence_distance_isolated_from_good_connection():
    result, raw, _ = load("isolated-ambiguous.pcap")
    good, bad = result.sessions
    assert known_bytes(good.streams[0], raw) == b"GOOD"
    assert "a_to_b:sequence_extent_ambiguous" in bad.diagnostics
    assert len(bad.streams) == 1  # Opposite direction remains available.


def test_checksum_warn_retains_bytes_reject_excludes_without_fake_stream():
    result, raw, packets = load("bad-checksum.pcap")
    assert "tcp_checksum_invalid" in packets[0].diagnostics
    assert known_bytes(result.sessions[0].streams[0], raw) == b"ABX"
    rejected, _, _ = load("bad-checksum.pcap", policy="reject")
    assert not rejected.sessions
    assert rejected.excluded_packet_ids == (packets[0].id,)


def test_delayed_initial_syn_reorders_endpoint_roles():
    result, raw, _ = load("delayed-syn.pcap")
    (session,) = result.sessions
    assert session.start_known and session.roles_known
    assert session.endpoint_a.port == 41000
    assert known_bytes(session.streams[0], raw) == b"HELLO"


def test_cancellation_and_explicit_resource_limits():
    with pytest.raises(WorkCancelled):
        load("ordered.pcap", cancelled=lambda: True)
    with pytest.raises(ValueError, match="max_sessions"):
        load("reused-tuple.pcap", ReconstructionSettings(max_sessions=1))
    result, _, _ = load(
        "reordered-retransmitted.pcap", ReconstructionSettings(max_comparison_bytes=1)
    )
    assert "a_to_b:max_comparison_bytes_exceeded" in result.sessions[0].diagnostics
    result, _, _ = load("gaps-overlaps.pcap", ReconstructionSettings(max_spans_per_stream=1))
    assert "a_to_b:max_spans_per_stream_exceeded" in result.sessions[0].diagnostics


def test_missing_bytes_recovered_by_later_retransmission():
    path = ROOT / "gaps-overlaps.pcap"
    packets = list(index_capture(path, CAPTURE, IndexSettings()))
    raw = path.read_bytes()
    damaged = packets[-1]
    complete = damaged.model_copy(update={"id": UUID(int=999), "index": 6, "payload_length": 5})

    def source(packet):
        return (
            b"IJKLM"
            if packet.id == complete.id
            else raw[
                packet.file_offset + packet.payload_offset : packet.file_offset
                + packet.payload_offset
                + packet.payload_length
            ]
        )

    result = reconstruct(CAPTURE, [*packets, complete], source)
    assert not any(i.status == "truncated" for i in result.sessions[0].streams[0].issues)


def test_syn_fin_retransmission_is_one_connection_without_control_bytes():
    result, raw, _ = load("syn-fin-retransmitted.pcap")
    (session,) = result.sessions
    assert session.closed
    stream = session.streams[0]
    assert stream.extent == 3
    assert known_bytes(stream, raw) == b"ONE"
    assert len(stream.spans[0].sources) == 2


def test_new_syn_without_observed_close_separates_instances_and_marks_missing_end():
    result, raw, _ = load("new-syn-without-close.pcap")
    old, new = result.sessions
    assert "connection_end_unavailable" in old.diagnostics
    assert "new_syn_before_previous_close" in new.diagnostics
    assert [known_bytes(s.streams[0], raw) for s in result.sessions] == [b"OLD", b"NEW"]


def test_simultaneous_open_never_claims_client_server_roles():
    result, raw, _ = load("simultaneous-open.pcap")
    (session,) = result.sessions
    assert session.start_known and not session.roles_known
    assert "simultaneous_open_roles_unknown" in session.diagnostics
    assert known_bytes(session.streams[0], raw) == b"HELLO"


def test_missing_prefix_and_fully_truncated_payload_are_explicit_ranges():
    result, raw, _ = load("missing-prefix.pcap")
    stream = result.sessions[0].streams[0]
    assert values(stream, raw)[0] == ("gap", 0, 5, set())
    assert stream.extent == 10
    result, raw, _ = load("truncated-zero.pcap")
    stream = result.sessions[0].streams[0]
    assert values(stream, raw) == [("truncated", 0, 5, set())]


def test_capture_interfaces_are_isolated_with_visible_identity_uncertainty():
    root = ROOT.parent
    packets = list(index_capture(root / "multi-interface.pcapng", CAPTURE, IndexSettings()))
    raw = (root / "multi-interface.pcapng").read_bytes()
    result = reconstruct(
        CAPTURE,
        packets,
        lambda p: raw[
            p.file_offset + p.payload_offset : p.file_offset + p.payload_offset + p.payload_length
        ],
    )
    assert len(result.sessions) == 3
    assert {(s.section_index, s.interface_id) for s in result.sessions} == {(0, 0), (0, 1), (1, 0)}
    assert all(
        "cross_observation_domain_identity_unknown" in s.diagnostics for s in result.sessions
    )


def test_delayed_payload_before_fin_reassembles_without_false_new_connection():
    result, raw, _ = load("late-payload-after-fin.pcap")
    (session,) = result.sessions
    assert session.closed
    assert known_bytes(session.streams[0], raw) == b"HELLO"
    assert session.streams[0].extent == 5
    assert not session.streams[0].issues
    assert "post_close_payload_identity_uncertain" in session.diagnostics


def test_conflicting_syn_ack_is_diagnosed_instead_of_selecting_an_origin():
    result, raw, _ = load("conflicting-server-syn.pcap")
    (session,) = result.sessions
    assert "b_to_a:conflicting_syn_sequence" in session.diagnostics
    assert known_bytes(session.streams[0], raw) == b"HELLO"
