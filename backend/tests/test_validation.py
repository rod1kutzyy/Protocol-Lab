from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import ByteRange, StreamRange
from protocol_lab.framing.engine import StreamInput
from protocol_lab.interpretation.schema import ProtocolModel
from protocol_lab.validation.engine import (
    CoverageCounter,
    capture_diagnostics,
    compare,
    matches_session,
    reconstruction_diagnostics,
    reconstruction_failures,
    validate_stream,
    values_hash,
)
from protocol_lab.validation.models import (
    CorpusSpec,
    ReconstructionFailure,
    StreamSnapshot,
    ValidationSummary,
)


def inputs(data=b"\x00\x03ABC\x00\x01Z", included=True, rule=None):
    run_id, capture_id, stream_id, session_id = (uuid4() for _ in range(4))
    stream = StreamSnapshot(
        id=stream_id,
        session_id=session_id,
        reconstruction_version="tcp-v1",
        reconstruction_policy="test",
        extent=len(data),
        direction="a_to_b",
        included=included,
    )
    capture = SimpleNamespace(id=capture_id, sha256="0" * 64)
    model = ProtocolModel.model_validate(
        dict(
            schema_version="interpretation-1",
            name="Length",
            framing={"rule": rule or {"kind": "length", "width": 2, "adjustment": 2}},
            fields=[
                dict(kind="int", name="n", width=2, signed=False, endian="big", constant=3),
                dict(kind="bytes", name="p", length={"field": "n"}),
            ],
        )
    )
    source = StreamInput(
        len(data),
        [(0, len(data), "known")] if data else [],
        lambda start, length: data[start : start + length],
    )
    return run_id, capture, stream, source, model


def test_corpus_runs_same_rules_and_reproduces_concrete_counterexample():
    args = inputs()
    result = list(validate_stream(*args))
    assert [r.status for r in result] == ["passed", "failed"]
    assert result[1].fields[0].value == "1"
    assert result[1].fields[0].anchor.byte_range == ByteRange(start=5, end=7)
    assert result[1].unknown_ranges[0].anchor.byte_range == ByteRange(start=7, end=8)
    assert result == list(validate_stream(*args))


def test_resource_limit_is_not_a_corpus_counterexample_and_diagnostics_survive():
    run, capture, stream, source, _ = inputs(b"\x03ABC", rule={"kind": "fixed", "size": 4})
    document = dict(
        schema_version="interpretation-1",
        name="Array",
        max_array_items=2,
        framing=dict(rule={"kind": "fixed", "size": 4}),
        fields=[
            dict(kind="int", name="n", width=1, signed=False, endian="big"),
            dict(
                kind="array",
                name="items",
                count={"field": "n"},
                fields=[dict(kind="int", name="v", width=1, signed=False, endian="big")],
            ),
        ],
    )
    model = ProtocolModel.model_validate(document)
    result = list(validate_stream(run, capture, stream, source, model))[0]
    assert result.status == "unknown" and result.technical_limit.name == "max_array_items"
    assert result.fields[0].value == "3"
    document["max_array_items"] = 3
    assert (
        list(validate_stream(run, capture, stream, source, ProtocolModel.model_validate(document)))[
            0
        ].status
        == "passed"
    )


def test_framing_technical_limit_reaches_corpus_unknown_range():
    run, capture, stream, source, model = inputs(
        b"<abcdef>", rule=dict(kind="markers", start_hex="3c", end_hex="3e")
    )
    document = model.model_dump(mode="json")
    document["framing"]["max_message_bytes"] = 4
    result = list(
        validate_stream(run, capture, stream, source, ProtocolModel.model_validate(document))
    )[0]
    assert result.status == "unknown" and result.kind == "leftover"
    assert result.technical_limit.maximum == "4"
    assert result.anchor.byte_range == ByteRange(start=0, end=8)


def test_full_coverage_includes_unframed_leftover_and_empty_or_filtered_stream():
    args = inputs(b"HELLOWORLD!", rule={"kind": "fixed", "size": 5})
    result = list(validate_stream(*args))
    assert [r.kind for r in result] == ["message", "message", "leftover"]
    assert result[-1].status == "unknown"
    excluded = list(validate_stream(*inputs(included=False)))[0]
    assert excluded.kind == "excluded" and excluded.anchor.byte_range.end == 8
    empty = list(validate_stream(*inputs(b"")))[0]
    assert empty.stream_id and empty.anchor is None and empty.status == "not_applicable"


def test_empty_streams_do_not_merge_by_capture_identity():
    args = inputs(b"")
    first = list(validate_stream(*args))[0]
    other = args[2].model_copy(update={"id": uuid4()})
    second = list(validate_stream(args[0], args[1], other, args[3], args[4]))[0]
    assert first.id != second.id


def test_bad_framing_marks_entire_stream_unknown_without_inventing_bytes():
    result = list(
        validate_stream(*inputs(rule={"kind": "manual", "ranges": [{"start": 0, "end": 100}]}))
    )[0]
    assert result.status == "unknown" and result.kind == "stream_diagnostic"
    assert result.anchor.byte_range == ByteRange(start=0, end=8)
    assert "Manual range" in result.diagnostic


def test_missing_and_ambiguous_data_are_not_passed():
    run, capture, stream, _, model = inputs(b"\x00\x03ABC")
    for problem, status in [
        ("gap", "unknown"),
        ("truncated", "unknown"),
        ("ambiguous", "ambiguous"),
    ]:
        source = StreamInput(
            5,
            [(0, 2, "known"), (2, 5, problem)],
            lambda start, length: b"\x00\x03"[start : start + length],
        )
        result = list(validate_stream(run, capture, stream, source, model))[0]
        assert result.status == status
        assert len(result.fields) == 1


def test_corpus_filter_scope_is_explicit_and_uses_connection_time_overlap():
    capture = uuid4()
    spec = CorpusSpec(
        capture_ids=[capture], address="192.0.2.1", port=9000, start_ns="10", end_ns="20"
    )
    session = SimpleNamespace(
        endpoint_a=SimpleNamespace(address="192.0.2.1", port=123),
        endpoint_b=SimpleNamespace(address="192.0.2.2", port=9000),
    )
    assert matches_session(spec, session, 0, 15)
    assert not matches_session(spec, session, None, None)
    assert not matches_session(spec, session, 21, 30)
    assert not matches_session(spec.model_copy(update={"port": 1}), session, 0, 15)
    with pytest.raises(ValidationError):
        CorpusSpec(capture_ids=[capture, capture])
    with pytest.raises(ValidationError):
        CorpusSpec(capture_ids=[capture], start_ns="20", end_ns="10")


def summary(
    capture,
    stream,
    start,
    end,
    status="passed",
    sha="a" * 64,
    kind="message",
    diagnostic="rules_executed",
):
    return ValidationSummary(
        id=uuid4(),
        capture_id=capture,
        stream_id=stream,
        session_id=uuid4(),
        anchor=StreamRange(
            stream_id=stream,
            reconstruction_version="tcp-v1",
            byte_range=ByteRange(start=start, end=end),
        ),
        framing_version="test",
        kind=kind,
        status=status,
        diagnostic=diagnostic,
        field_count=1,
        unknown_range_count=0,
        values_sha256=sha,
    )


def test_comparison_matches_source_ranges_not_new_message_ids():
    capture, stream = uuid4(), uuid4()
    left = [
        summary(capture, stream, 0, 5),
        summary(capture, stream, 5, 10),
        summary(capture, stream, 10, 15),
    ]
    right = [
        summary(capture, stream, 0, 5, "failed"),
        summary(capture, stream, 5, 10, sha="b" * 64),
        summary(capture, stream, 10, 15),
    ]
    result = list(compare(iter(left), iter(right)))
    assert [r.change for r in result] == ["status", "values"]
    assert result[0].left.id != result[0].right.id


def test_same_unknown_status_with_different_resource_limits_is_a_visible_difference():
    from protocol_lab.domain.diagnostics import technical_limit

    left = summary(uuid4(), uuid4(), 0, 5, status="unknown", diagnostic="max_array_items_exceeded")
    left = left.model_copy(update={"technical_limit": technical_limit("max_array_items", 4, 2)})
    right = left.model_copy(update={"technical_limit": technical_limit("max_array_items", 4, 3)})
    changes = list(compare(iter([left]), iter([right])))
    assert len(changes) == 1 and changes[0].change == "diagnostic"


def test_reframed_ranges_are_added_removed_not_falsely_matched():
    capture, stream = uuid4(), uuid4()
    result = list(
        compare(
            iter([summary(capture, stream, 0, 5)]),
            iter([summary(capture, stream, 0, 3), summary(capture, stream, 3, 5)]),
        )
    )
    assert sorted(r.change for r in result) == ["added", "added", "removed"]


def test_coverage_accounts_all_status_bytes_and_partial_leaf_values():
    args = inputs()
    source = SimpleNamespace(
        streams=[args[2]], reconstruction_id=uuid4(), packet_count=5, eligible_packets=4
    )
    counter = CoverageCounter(SimpleNamespace(sources=[source]))
    for item in validate_stream(*args):
        counter.add(item)
    coverage = counter.result()
    assert coverage.stream_bytes == coverage.selected_stream_bytes == 8
    assert sum(coverage.byte_counts.values()) == 8
    assert coverage.message_counts["passed"] == 1 and coverage.message_counts["failed"] == 1
    assert coverage.decoded_leaf_bytes == 7 and coverage.undecoded_bytes == 1
    assert coverage.noneligible_packets == 1
    assert set(coverage.counts) == {"passed", "failed", "unknown", "ambiguous", "not_applicable"}


def test_cancellation_never_returns_complete_validation():
    with pytest.raises(WorkCancelled):
        list(validate_stream(*inputs(), cancelled=lambda: True))


def test_value_fingerprint_ignores_new_validation_id():
    args = inputs()
    a = list(validate_stream(*args))[0]
    b = list(validate_stream(uuid4(), *args[1:]))[0]
    assert a.id != b.id and values_hash(a.fields) == values_hash(b.fields)


def test_unframed_ambiguous_bytes_and_source_uncertainty_are_visible_in_summary():
    run, capture, stream, _, model = inputs(b"ABCDEF", rule={"kind": "fixed", "size": 5})
    stream = stream.model_copy(update={"data_status_bytes": {"known": 3, "gap": 2, "ambiguous": 1}})
    model = model.model_copy(
        update={
            "fields": ProtocolModel.model_validate(
                dict(
                    schema_version="interpretation-1",
                    name="Raw",
                    framing={"rule": {"kind": "fixed", "size": 5}},
                    fields=[dict(kind="bytes", name="raw", length="remaining")],
                )
            ).fields
        }
    )
    source = StreamInput(
        6,
        [(0, 3, "known"), (3, 5, "gap"), (5, 6, "ambiguous")],
        lambda start, length: b"ABC"[start : start + length],
    )
    result = list(validate_stream(run, capture, stream, source, model))
    assert [r.status for r in result] == ["unknown", "ambiguous"]
    snapshot = SimpleNamespace(
        sources=[
            SimpleNamespace(
                streams=[stream], reconstruction_id=uuid4(), packet_count=2, eligible_packets=2
            )
        ]
    )
    counter = CoverageCounter(snapshot)
    for item in result:
        counter.add(item)
    coverage = counter.result()
    assert coverage.unavailable_source_bytes == 2 and coverage.ambiguous_source_bytes == 1
    assert coverage.unframed_bytes == 1 and coverage.undecoded_bytes == 6
    assert sum(coverage.byte_counts.values()) == 6


def test_changed_reconstruction_coordinates_are_not_silently_compared():
    capture, stream = uuid4(), uuid4()
    left = summary(capture, stream, 0, 5)
    right = left.model_copy(
        update={
            "id": uuid4(),
            "anchor": left.anchor.model_copy(update={"reconstruction_version": "tcp-v2"}),
        }
    )
    assert sorted(item.change for item in compare(iter([left]), iter([right]))) == [
        "added",
        "removed",
    ]


@pytest.mark.parametrize(
    "included,direction,expected",
    [(True, "both", True), (True, "a_to_b", True), (True, "b_to_a", False), (False, "both", False)],
)
def test_reconstruction_failures_respect_session_and_direction_filters(
    included, direction, expected
):
    session = SimpleNamespace(
        id=uuid4(),
        streams=[SimpleNamespace(direction="b_to_a")],
        diagnostics=["connection_start_unavailable", "a_to_b:sequence_extent_ambiguous"],
    )
    (failure,) = reconstruction_failures(session, included, direction)
    assert failure.session_id == session.id
    assert failure.direction == "a_to_b" and failure.included is expected
    assert failure.diagnostic == "a_to_b:sequence_extent_ambiguous"
    capture = SimpleNamespace(id=uuid4(), reconstruction_failures=(failure,))
    (item,) = reconstruction_diagnostics(uuid4(), capture)
    assert item.status == ("unknown" if expected else "not_applicable")
    assert item.anchor is None and item.stream_id is None
    assert item.session_id == session.id and item.direction == "a_to_b"
    assert not item.fields and not item.unknown_ranges


def test_reconstruction_diagnostics_have_distinct_identity_and_compare_without_byte_anchors():
    session = uuid4()
    failures = tuple(
        ReconstructionFailure(
            session_id=id,
            direction=direction,
            included=True,
            diagnostic="direction_unavailable",
        )
        for id, direction in [(session, "a_to_b"), (session, "b_to_a"), (uuid4(), "a_to_b")]
    )
    capture = SimpleNamespace(id=uuid4(), reconstruction_failures=failures)

    def summaries(included):
        scoped = SimpleNamespace(
            id=capture.id,
            reconstruction_failures=tuple(
                failure.model_copy(update={"included": included}) for failure in failures
            ),
        )
        return sorted(
            [
                ValidationSummary(
                    **item.model_dump(exclude={"fields", "unknown_ranges"}),
                    field_count=0,
                    unknown_range_count=0,
                    values_sha256=values_hash(()),
                )
                for item in reconstruction_diagnostics(uuid4(), scoped)
            ],
            key=lambda item: (str(item.session_id), item.direction),
        )

    # Details are omitted from summaries, as they are by the storage adapter.
    left = summaries(True)
    assert len({item.id for item in left}) == 3
    assert len(list(compare(iter(left), iter(summaries(True))))) == 0
    assert [item.change for item in compare(iter(left), iter(summaries(False)))] == ["status"] * 3


def test_failed_directions_outside_scope_do_not_create_an_extra_unknown_capture():
    session = SimpleNamespace(
        id=uuid4(),
        streams=[],
        diagnostics=["a_to_b:sequence_extent_ambiguous", "b_to_a:conflicting_syn_sequence"],
    )
    capture = SimpleNamespace(
        id=uuid4(),
        reconstruction_id=uuid4(),
        streams=(),
        packet_count=4,
        eligible_packets=4,
        diagnostics={},
        reconstruction_failures=reconstruction_failures(session, included=False),
    )
    assert list(capture_diagnostics(uuid4(), capture)) == []
    assert [item.status for item in reconstruction_diagnostics(uuid4(), capture)] == [
        "not_applicable",
        "not_applicable",
    ]
