import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import ByteRange, StreamRange
from protocol_lab.framing.engine import Piece, StreamInput
from protocol_lab.interpretation.engine import compile_model, parse_message
from protocol_lab.interpretation.schema import ProtocolModel, canonical, json_schema


def document(fields, **kwargs):
    value = dict(
        schema_version="interpretation-1",
        name="Test",
        framing=dict(rule=dict(kind="fixed", size=5)),
        fields=fields,
    )
    value.update(kwargs)
    return value


def integer(name, width=1, signed=False, endian="big", **kwargs):
    return dict(kind="int", name=name, width=width, signed=signed, endian=endian, **kwargs)


def parse(doc, data, ranges=None, kind="message", cancelled=lambda: False):
    model = ProtocolModel.model_validate(doc)
    stream = uuid4()
    source = StreamInput(
        len(data),
        ranges or [(0, len(data), "known")],
        lambda start, length: data[start : start + length],
    )
    piece = Piece(
        id=uuid4(),
        framing_version="test",
        kind=kind,
        anchor=StreamRange(
            stream_id=stream,
            reconstruction_version="tcp-v1",
            byte_range=ByteRange(start=0, end=len(data)),
        ),
        boundary_status="known",
        data_status="known",
        diagnostic="test",
    )
    return parse_message(model, compile_model(model), piece, source, cancelled)


@pytest.mark.parametrize("width", [1, 2, 4, 8])
@pytest.mark.parametrize("signed,value", [(False, 1), (True, -2)])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_integer_types(width, signed, value, endian):
    result = parse(
        document([integer("value", width, signed, endian)]),
        value.to_bytes(width, endian, signed=signed),
    )
    assert result.status == "passed"
    assert result.fields[0].value == str(value)
    assert result.fields[0].anchor.byte_range == ByteRange(start=0, end=width)


def test_interpretation_2_delimited_bytes_requires_and_tracks_terminator():
    field = dict(
        kind="delimited_bytes",
        name="payload",
        terminator_hex="0d0a",
        max_length=16,
    )
    doc = document([field], schema_version="interpretation-2")
    result = parse(doc, b"abc\r\n")
    assert result.status == "passed"
    assert (result.fields[0].kind, result.fields[0].value, result.fields[0].length) == (
        "delimited_bytes",
        b"abc".hex(),
        5,
    )
    included = parse(
        document([{**field, "include_terminator": True}], schema_version="interpretation-2"),
        b"abc\r\n",
    )
    assert included.fields[0].value == b"abc\r\n".hex()
    missing = parse(doc, b"abc")
    assert missing.status == "failed"
    assert missing.diagnostic == "field_exceeds_message"
    bounded = parse(
        document([{**field, "max_length": 3}], schema_version="interpretation-2"),
        b"abcdef",
    )
    assert bounded.status == "unknown"
    assert bounded.diagnostic == "max_delimited_length_exceeded"
    with pytest.raises(ValidationError, match="interpretation-2"):
        parse(document([field]), b"abc\r\n")


def test_large_integer_is_exact_decimal_string():
    result = parse(document([integer("value", 8)]), (2**64 - 1).to_bytes(8, "big"))
    assert result.fields[0].value == "18446744073709551615"
    assert json.loads(result.model_dump_json())["fields"][0]["value"] == "18446744073709551615"


def test_variable_bytes_and_length_checks_reused_without_edits():
    doc = document(
        [integer("size", 2), dict(kind="bytes", name="payload", length={"field": "size"})],
        checks=[dict(kind="length", field="payload", expected={"field": "size"})],
    )
    for data in (b"\x00\x03ABC", b"\x00\x05DEFGH", b"\x00\x01Z"):
        result = parse(doc, data)
        assert result.status == "passed"
        assert result.fields[1].value == data[2:].hex()
        assert result.fields[1].anchor.byte_range == ByteRange(start=2, end=len(data))


def test_arrays_and_switch():
    doc = document(
        [
            integer("count"),
            dict(
                kind="array",
                name="entries",
                count={"field": "count"},
                fields=[
                    integer("tag"),
                    dict(
                        kind="switch",
                        name="body",
                        selector="tag",
                        cases={
                            "1": [integer("value", 2, True, "little")],
                            "2": [dict(kind="bytes", name="raw", length=2)],
                        },
                    ),
                ],
            ),
        ]
    )
    result = parse(doc, b"\x02\x01\xfe\xff\x02AB")
    assert result.status == "passed"
    assert [
        (f.path, f.value, f.offset, f.length) for f in result.fields if f.kind in {"int", "bytes"}
    ] == [
        ("count", "2", 0, 1),
        ("entries[0].tag", "1", 1, 1),
        ("entries[0].body.value", "-2", 2, 2),
        ("entries[1].tag", "2", 4, 1),
        ("entries[1].body.raw", "4142", 5, 2),
    ]


def test_unknown_variant_retains_header_and_tail():
    result = parse(
        document(
            [
                integer("tag"),
                dict(kind="switch", name="body", selector="tag", cases={"1": [integer("value")]}),
            ]
        ),
        b"\x03ABC",
    )
    assert result.status == "unknown"
    assert result.diagnostic == "unconfigured_variant"
    assert result.fields[0].value == "3"
    assert result.unknown_ranges[0].anchor.byte_range == ByteRange(start=1, end=4)


@pytest.mark.parametrize(
    "data,status,reason",
    [(b"\x03", "failed", "field_exceeds_message"), (b"\x00ABC", "unknown", "uninterpreted_tail")],
)
def test_malformed_length_and_unknown_tail(data, status, reason):
    result = parse(
        document([integer("n"), dict(kind="bytes", name="p", length={"field": "n"})]), data
    )
    assert result.status == status
    assert result.diagnostic == reason


@pytest.mark.parametrize(
    "field,data,diagnostic",
    [
        (integer("x", constant=4), b"\x05", "constant_check_failed"),
        (integer("x", minimum=4, maximum=6), b"\x03", "range_check_failed"),
        (
            dict(kind="bytes", name="x", length=2, constant_hex="aabb"),
            b"AB",
            "constant_check_failed",
        ),
    ],
)
def test_declarative_checks(field, data, diagnostic):
    result = parse(document([field]), data)
    assert result.status == "failed"
    assert result.diagnostic.endswith(diagnostic)
    assert result.fields


def test_length_mismatch_and_formula():
    doc = document(
        [integer("n"), dict(kind="bytes", name="payload", length=3)],
        checks=[
            dict(kind="length", field="payload", expected={"field": "n", "multiplier": 2, "add": 1})
        ],
    )
    assert parse(doc, b"\x01ABC").status == "passed"
    assert parse(doc, b"\x02ABC").diagnostic == "payload:length_check_failed"


@pytest.mark.parametrize(
    "status,expected", [("gap", "unknown"), ("truncated", "unknown"), ("ambiguous", "ambiguous")]
)
def test_no_guessing_unknown_payload(status, expected):
    result = parse(
        document([integer("n"), dict(kind="bytes", name="payload", length={"field": "n"})]),
        b"\x03ABC",
        [(0, 1, "known"), (1, 3, status), (3, 4, "known")],
    )
    assert result.status == expected
    assert [f.path for f in result.fields] == ["n"]
    assert [r.reason for r in result.unknown_ranges] == [status, "uninterpreted"]


def test_remaining_and_bounded_preview():
    result = parse(document([dict(kind="bytes", name="raw", length="remaining")]), b"A" * 100)
    assert result.status == "passed" and result.fields[0].preview_truncated
    assert len(result.fields[0].value) == 128 and result.fields[0].length == 100


def test_limits_cancellation_and_leftovers():
    doc = document(
        [
            integer("n"),
            dict(kind="array", name="items", count={"field": "n"}, fields=[integer("v")]),
        ],
        max_array_items=2,
    )
    limited = parse(doc, b"\x03ABC")
    assert limited.diagnostic == "max_array_items_exceeded" and limited.status == "unknown"
    assert limited.technical_limit.name == "max_array_items"
    assert limited.technical_limit.observed == "3" and limited.technical_limit.maximum == "2"
    doc["max_array_items"] = 3
    doc["max_decoded_fields"] = 2
    limited = parse(doc, b"\x03ABC")
    assert limited.diagnostic == "max_decoded_fields_exceeded" and limited.status == "unknown"
    with pytest.raises(WorkCancelled):
        parse(document([integer("x")]), b"X", cancelled=lambda: True)
    result = parse(document([integer("x")]), b"AB", kind="leftover")
    assert result.status == "not_applicable" and result.unknown_ranges


@pytest.mark.parametrize(
    "fields",
    [
        [dict(kind="bytes", name="bad", length={"field": "later"}), integer("later")],
        [integer("x"), integer("x")],
        [dict(kind="int", name="_private", width=1, signed=False, endian="big")],
        [dict(kind="bytes", name="bad", length='__import__("os").system("x")')],
        [
            integer("tag"),
            dict(kind="switch", name="body", selector="tag", cases={"01": [integer("x")]}),
        ],
        [integer("x", constant=256)],
        [integer("x", width=True)],
        [integer("x", signed="false")],
        [dict(kind="bytes", name="bytes", length=-1)],
    ],
)
def test_invalid_models_rejected(fields):
    with pytest.raises(ValidationError):
        ProtocolModel.model_validate(document(fields))


def test_schema_and_canonical_are_deterministic():
    model = ProtocolModel.model_validate(document([integer("x")]))
    assert ProtocolModel.model_validate_json(canonical(model)) == model
    schema = json_schema()
    assert schema["$id"] == "urn:protocol-lab:interpretation-2"
    assert schema["additionalProperties"] is False


def test_same_construct_model_on_variable_messages_in_real_captures():
    import hashlib
    from pathlib import Path

    from protocol_lab.capture.index import IndexSettings, index_capture
    from protocol_lab.framing.engine import frame
    from protocol_lab.storage.framing import FramingStore
    from protocol_lab.tcp.reassembly import reconstruct

    doc = document(
        [
            integer("payload_length", 2),
            integer("count"),
            dict(
                kind="array",
                name="entries",
                count={"field": "count"},
                fields=[
                    integer("tag"),
                    dict(
                        kind="switch",
                        name="body",
                        selector="tag",
                        cases={
                            "1": [integer("value", 2, True, "little")],
                            "2": [dict(kind="bytes", name="raw", length=2)],
                        },
                    ),
                ],
            ),
        ]
    )
    doc["framing"] = {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
    model = ProtocolModel.model_validate(doc)
    results = []
    for name in ["arrays-variants.pcap", "arrays-new-parameters.pcap"]:
        path = Path(__file__).resolve().parents[2] / "tests/fixtures/interpretation" / name
        capture_id = uuid4()
        raw = path.read_bytes()
        packets = list(index_capture(path, capture_id, IndexSettings()))
        stream = (
            reconstruct(
                capture_id,
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

        class TCP:
            def spans(self, stream_id, current=stream):
                return iter(current.spans)

        repository = object.__new__(FramingStore)
        repository.tcp = TCP()
        with path.open("rb") as file:
            source = repository.input(stream, file)
            framing = frame(
                stream.id,
                "tcp-v1",
                capture_id,
                hashlib.sha256(raw).hexdigest(),
                source,
                model.framing,
            )
            results.extend(
                parse_message(model, compile_model(model), piece, source)
                for piece in framing.pieces
            )
    assert [r.status for r in results] == ["passed"] * 4
    assert [[f.value for f in r.fields if f.path == "count"] for r in results] == [
        ["2"],
        ["1"],
        ["0"],
        ["1"],
    ]
    assert [f.value for f in results[0].fields if f.path == "entries[0].body.value"] == ["-2"]
    assert [f.value for f in results[3].fields if f.path == "entries[0].body.raw"] == ["4344"]


def test_cancellation_during_large_byte_read_is_not_swallowed_by_construct():
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        return calls >= 4

    with pytest.raises(WorkCancelled):
        parse(
            document([dict(kind="bytes", name="raw", length="remaining")]),
            b"A" * 100000,
            cancelled=cancel,
        )


def test_empty_fields_have_no_invented_source_range():
    result = parse(
        document([integer("n"), dict(kind="bytes", name="empty", length={"field": "n"})]), b"\x00"
    )
    assert result.status == "passed"
    assert result.fields[1].anchor is None and result.fields[1].length == 0


def test_unknown_range_limit_never_silently_truncates_coverage():
    doc = document([integer("first")], max_decoded_fields=1)
    with pytest.raises(ValueError, match="Unknown range count"):
        parse(doc, b"ABCD", [(0, 1, "known"), (1, 2, "gap"), (2, 3, "known"), (3, 4, "ambiguous")])


def test_array_resource_limit_is_unknown_and_increasing_budget_does_not_change_evidence():
    doc = document(
        [
            integer("n"),
            dict(kind="array", name="items", count={"field": "n"}, fields=[integer("value")]),
        ],
        max_array_items=2,
    )
    limited = parse(doc, b"\x03ABC")
    assert limited.status == "unknown" and limited.diagnostic == "max_array_items_exceeded"
    assert limited.fields[0].value == "3"
    assert limited.unknown_ranges[0].anchor.byte_range == ByteRange(start=1, end=4)
    doc["max_array_items"] = 3
    complete = parse(doc, b"\x03ABC")
    assert complete.status == "passed" and complete.technical_limit is None
    assert complete.fields[0].value == limited.fields[0].value
    assert complete.fields[0].anchor.byte_range == limited.fields[0].anchor.byte_range


def test_negative_computed_length_is_a_rule_failure_not_resource_exhaustion():
    result = parse(
        document(
            [
                integer("n"),
                dict(kind="bytes", name="payload", length={"field": "n", "add": -2}),
            ]
        ),
        b"\x01ABC",
    )
    assert result.status == "failed" and result.technical_limit is None
    assert result.diagnostic == "negative_computed_length_or_count"


def test_huge_computed_length_is_unknown_with_exact_limit_and_legacy_result_is_readable():
    from protocol_lab.interpretation.engine import MessageResult

    result = parse(
        document(
            [
                integer("n", width=8),
                dict(kind="bytes", name="payload", length={"field": "n"}),
            ]
        ),
        (2**64 - 1).to_bytes(8, "big"),
    )
    assert result.status == "unknown" and result.technical_limit.observed == str(2**64 - 1)
    legacy = result.model_dump(mode="json")
    legacy.pop("technical_limit")
    legacy["status"], legacy["diagnostic"] = "failed", "computed_length_or_count_outside_limit"
    old = MessageResult.model_validate(legacy)
    assert old.status == "failed" and old.technical_limit is None


def test_construct_wrapped_read_problem_and_cancellation_preserve_original_status():
    # Exercise the ConstructError path, not just exceptions raised by our wrappers.
    from construct import ConstructError

    from protocol_lab.domain.diagnostics import technical_limit
    from protocol_lab.interpretation.engine import Problem

    class WrappedParser:
        def __init__(self, problem):
            self.problem = problem

        def parse_stream(self, stream, **_):
            stream.error = self.problem
            raise ConstructError("wrapped")

    from protocol_lab.interpretation.engine import parse_message
    from protocol_lab.interpretation.schema import ProtocolModel

    model = ProtocolModel.model_validate(document([integer("x")]))
    from protocol_lab.framing.engine import FramingSpec, frame

    source = StreamInput(1, [(0, 1, "known")], lambda *_: b"X")
    piece = frame(
        uuid4(), "tcp-v1", uuid4(), "0" * 64, source, FramingSpec(rule={"kind": "fixed", "size": 1})
    ).pieces[0]
    limit = technical_limit("max_array_items", 3, 2)
    result = parse_message(
        model, WrappedParser(Problem("max_array_items_exceeded", limit)), piece, source
    )
    assert result.status == "unknown" and result.technical_limit == limit
    with pytest.raises(WorkCancelled):
        parse_message(model, WrappedParser(WorkCancelled()), piece, source)
