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
    return dict(
        schema_version="interpretation-1",
        name="Test",
        framing=dict(rule=dict(kind="fixed", size=5)),
        fields=fields,
        **kwargs,
    )


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
    assert parse(doc, b"\x03ABC").diagnostic == "computed_length_or_count_outside_limit"
    doc["max_array_items"] = 3
    doc["max_decoded_fields"] = 2
    assert parse(doc, b"\x03ABC").diagnostic == "max_decoded_fields_exceeded"
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
    assert schema["$id"] == "urn:protocol-lab:interpretation-1"
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
