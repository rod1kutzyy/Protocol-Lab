import hashlib
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from protocol_lab.capture.index import IndexSettings, WorkCancelled, index_capture
from protocol_lab.framing.engine import FramingSpec, StreamInput, frame
from protocol_lab.tcp.reassembly import reconstruct

STREAM, CAPTURE = UUID(int=1), UUID(int=2)


def execute(data, rule, ranges=None, **options):
    source = StreamInput(
        len(data),
        ranges or ([(0, len(data), "known")] if data else []),
        lambda offset, length: data[offset : offset + length],
    )
    return frame(STREAM, "tcp-v1", CAPTURE, "0" * 64, source, FramingSpec(rule=rule, **options))


def intervals(result):
    return [
        (p.kind, p.anchor.byte_range.start, p.anchor.byte_range.end, p.data_status, p.diagnostic)
        for p in result.pieces
    ]


def test_fixed_manual_and_tail_account_for_entire_stream():
    fixed = execute(b"HELLOWORLD!", {"kind": "fixed", "size": 5})
    assert [(p.kind, p.anchor.byte_range.start, p.anchor.byte_range.end) for p in fixed.pieces] == [
        ("message", 0, 5),
        ("message", 5, 10),
        ("leftover", 10, 11),
    ]
    manual = execute(
        b"HELLOWORLD!",
        {"kind": "manual", "ranges": [{"start": 2, "end": 5}, {"start": 5, "end": 9}]},
    )
    assert manual.message_count == 2 and manual.leftover_bytes == 4
    assert (
        manual.pieces[0].anchor.byte_range.start == 0
        and manual.pieces[-1].anchor.byte_range.end == 11
    )
    assert manual.pieces[1].diagnostic == "manual_boundary_hypothesis"
    assert execute(b"", {"kind": "fixed", "size": 5}).pieces == ()


@pytest.mark.parametrize("endian", ["big", "little"])
@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_length_width_endian_formula_and_variable_messages(endian, width):
    prefix = b"XX"
    data = b"".join(prefix + n.to_bytes(width, endian) + b"A" * (n * 2) for n in (1, 3))
    result = execute(
        data,
        {
            "kind": "length",
            "offset": 2,
            "width": width,
            "endian": endian,
            "multiplier": 2,
            "adjustment": width + 2,
        },
    )
    assert result.message_count == 2 and result.leftover_bytes == 0
    assert result.pieces[0].anchor.byte_range.end == width + 4
    assert result.pieces[1].anchor.byte_range.end == len(data)


def test_length_includes_header_and_negative_adjustment():
    result = execute(b"\x05AB\x04C", {"kind": "length", "width": 1, "adjustment": -2})
    assert result.message_count == 2 and result.leftover_bytes == 0


@pytest.mark.parametrize(
    "data,reason",
    [
        (b"\x00\x00more", "invalid_length_no_resynchronization"),
        (b"\x00\x08abc", "incomplete_length_message"),
        (b"\x00", "incomplete_length_header"),
    ],
)
def test_malformed_or_incomplete_length_leaves_visible_counterexample(data, reason):
    result = execute(data, {"kind": "length", "width": 2})
    assert result.message_count == 0 and result.leftover_bytes == len(data)
    assert result.pieces[0].diagnostic == reason
    assert result.pieces[0].boundary_status == "uncertain"


def test_unknown_length_header_stops_without_guessing_later_alignment():
    result = execute(
        b"\x03AB\x03CD", {"kind": "length", "width": 1}, [(0, 1, "ambiguous"), (1, 6, "known")]
    )
    assert result.message_count == 0 and result.uncertain_bytes == 6
    assert result.pieces[0].diagnostic == "unknown_length_header_no_resynchronization"


def test_fixed_boundaries_keep_missing_and_ambiguous_payload_explicit():
    result = execute(
        b"AB00CD00",
        {"kind": "fixed", "size": 4},
        [(0, 2, "known"), (2, 3, "gap"), (3, 4, "ambiguous"), (4, 6, "known"), (6, 8, "truncated")],
    )
    assert [p.data_status for p in result.pieces] == ["mixed", "incomplete"]
    assert all(p.boundary_status == "known" for p in result.pieces)
    assert result.uncertain_bytes == 8


def test_markers_include_delimiters_and_report_prefix_and_suffix():
    result = execute(b"x<abc><d>tail", {"kind": "markers", "start_hex": "3c", "end_hex": "3e"})
    assert result.message_count == 2 and result.leftover_bytes == 5
    assert [
        (p.anchor.byte_range.start, p.anchor.byte_range.end)
        for p in result.pieces
        if p.kind == "message"
    ] == [(1, 6), (6, 9)]


def test_marker_search_crosses_read_boundaries_but_never_unknown_bytes():
    data = b"x" * 65535 + b"\xaa\xbbBODY\xcc\xdd"
    result = execute(data, {"kind": "markers", "start_hex": "aabb", "end_hex": "ccdd"})
    assert result.message_count == 1 and result.pieces[-1].anchor.byte_range.start == 65535
    result = execute(
        b"<abc00><ok>",
        {"kind": "markers", "start_hex": "3c", "end_hex": "3e"},
        [(0, 4, "known"), (4, 6, "gap"), (6, 11, "known")],
    )
    assert [
        (p.anchor.byte_range.start, p.anchor.byte_range.end)
        for p in result.pieces
        if p.kind == "message"
    ] == [(7, 11)]
    assert result.leftover_bytes == 7
    assert any(p.data_status == "incomplete" for p in result.pieces)


def test_marker_stop_reasons_distinguish_limit_gap_and_capture_end():
    rule = dict(kind="markers", start_hex="3c", end_hex="3e")
    limited = execute(b"<abcdef>", rule, max_message_bytes=4)
    tail = limited.pieces[0]
    assert tail.diagnostic == "end_marker_search_limit_exceeded"
    assert tail.technical_limit.name == "max_message_bytes"
    assert tail.technical_limit.observed_is_lower_bound
    assert tail.anchor.byte_range.end == 8 and limited.leftover_bytes == 8
    end = execute(b"<abc", rule)
    assert end.pieces[0].diagnostic == "end_marker_not_found_before_stream_end"
    assert end.pieces[0].technical_limit is None
    gap = execute(b"<abc??>", rule, [(0, 4, "known"), (4, 6, "gap"), (6, 7, "known")])
    assert gap.pieces[0].diagnostic == "end_marker_search_interrupted_by_unknown_bytes"
    assert gap.pieces[0].technical_limit is None and gap.leftover_bytes == 7
    assert execute(b"<ab>", rule, max_message_bytes=4).message_count == 1


def test_length_limit_is_distinct_from_impossible_length_and_keeps_full_extent():
    limited = execute(b"\x08ABCDEFG", {"kind": "length", "width": 1}, max_message_bytes=4)
    assert limited.pieces[0].diagnostic == "max_message_bytes_exceeded_no_resynchronization"
    assert limited.pieces[0].technical_limit.observed == "8"
    assert limited.leftover_bytes == 8
    assert (
        execute(b"\x08ABCDEFG", {"kind": "length", "width": 1}, max_message_bytes=8).message_count
        == 1
    )
    invalid = execute(b"\x00ABCDEFG", {"kind": "length", "width": 1})
    assert invalid.pieces[0].diagnostic == "invalid_length_no_resynchronization"
    assert invalid.pieces[0].technical_limit is None


def test_historical_framing_result_keeps_engine_and_combined_diagnostic():
    from protocol_lab.framing.engine import FramingResult, identity

    result = execute(b"<abc", dict(kind="markers", start_hex="3c", end_hex="3e"))
    old = result.model_dump(mode="json")
    old["engine_version"] = "framing-v1"
    for piece in old["pieces"]:
        piece.pop("technical_limit")
        piece["diagnostic"] = "end_marker_not_found_or_limit_exceeded"
    historic = FramingResult.model_validate(old)
    assert historic.engine_version == "framing-v1"
    assert historic.pieces[0].diagnostic == "end_marker_not_found_or_limit_exceeded"
    assert historic.pieces[0].technical_limit is None
    assert result.id == identity(STREAM, "tcp-v1", "0" * 64, result.spec)


def test_limits_cancel_schema_and_immutable_revision():
    rule = {"kind": "fixed", "size": 2}
    result = execute(b"ABCD", rule)
    assert result == execute(b"ABCD", rule)
    assert result.id != execute(b"ABCD", {"kind": "fixed", "size": 4}).id
    with pytest.raises(ValueError, match="max_pieces"):
        execute(b"ABCD", rule, max_pieces=1)
    with pytest.raises(ValidationError):
        FramingSpec(
            rule={"kind": "manual", "ranges": [{"start": 2, "end": 4}, {"start": 3, "end": 5}]}
        )
    with pytest.raises(ValidationError):
        FramingSpec(rule={"kind": "length", "expression": "eval(anything)"})
    with pytest.raises(ValueError, match="extent"):
        execute(b"A", {"kind": "manual", "ranges": [{"start": 0, "end": 2}]})
    source = StreamInput(1, [(0, 1, "known")], lambda offset, length: b"A")
    with pytest.raises(WorkCancelled):
        frame(STREAM, "tcp-v1", CAPTURE, "0" * 64, source, FramingSpec(rule=rule), lambda: True)


def test_same_message_across_packets_and_multiple_messages_in_one_packet():
    root = Path(__file__).resolve().parents[2] / "tests/fixtures/tcp"
    for name in ("ordered.pcap", "reordered-retransmitted.pcap"):
        raw = (root / name).read_bytes()
        packets = list(index_capture(root / name, CAPTURE, IndexSettings()))
        stream = (
            reconstruct(
                CAPTURE,
                packets,
                lambda p, raw=raw: raw[
                    p.file_offset + p.payload_offset : p.file_offset
                    + p.payload_offset
                    + p.payload_length
                ],
            )
            .sessions[0]
            .streams[0]
        )

        def read(offset, length, stream=stream, raw=raw):
            out = b""
            for span in stream.spans:
                left = max(offset, span.byte_range.start)
                right = min(offset + length, span.byte_range.end)
                if left < right:
                    position = span.sources[0].file_offset + left - span.byte_range.start
                    out += raw[position : position + right - left]
            return out

        source = StreamInput(
            stream.extent,
            [(s.byte_range.start, s.byte_range.end, s.status) for s in stream.spans],
            read,
        )
        result = frame(
            stream.id,
            "tcp-v1",
            CAPTURE,
            hashlib.sha256(raw).hexdigest(),
            source,
            FramingSpec(rule={"kind": "fixed", "size": 7}),
        )
        assert read(0, result.pieces[0].anchor.byte_range.end) == b"HELLOWO"
        assert result.message_count == 1 and result.leftover_bytes == 3
        two = frame(
            stream.id,
            "tcp-v1",
            CAPTURE,
            hashlib.sha256(raw).hexdigest(),
            source,
            FramingSpec(rule={"kind": "fixed", "size": 5}),
        )
        assert two.message_count == 2 and two.leftover_bytes == 0


@pytest.mark.parametrize(
    "name,rule,messages,leftovers",
    [
        ("length-big.pcap", {"kind": "length", "width": 2, "endian": "big", "adjustment": 2}, 3, 0),
        (
            "length-little.pcap",
            {"kind": "length", "width": 2, "endian": "little", "adjustment": 2},
            3,
            0,
        ),
        ("markers.pcap", {"kind": "markers", "start_hex": "aabb", "end_hex": "ccdd"}, 2, 9),
        ("length-incomplete.pcap", {"kind": "length", "width": 2, "adjustment": 2}, 1, 3),
    ],
)
def test_generated_framing_fixtures(name, rule, messages, leftovers):
    from protocol_lab.storage.framing import FramingStore

    path = Path(__file__).resolve().parents[2] / "tests/fixtures/framing" / name
    raw = path.read_bytes()
    packets = list(index_capture(path, CAPTURE, IndexSettings()))
    stream = (
        reconstruct(
            CAPTURE,
            packets,
            lambda p: raw[
                p.file_offset + p.payload_offset : p.file_offset
                + p.payload_offset
                + p.payload_length
            ],
        )
        .sessions[0]
        .streams[0]
    )

    class TCP:
        def spans(self, stream_id):
            return iter(stream.spans)

    repository = object.__new__(FramingStore)
    repository.tcp = TCP()
    with path.open("rb") as file:
        result = frame(
            stream.id,
            "tcp-v1",
            CAPTURE,
            hashlib.sha256(raw).hexdigest(),
            repository.input(stream, file),
            FramingSpec(rule=rule),
        )
    assert result.message_count == messages and result.leftover_bytes == leftovers
