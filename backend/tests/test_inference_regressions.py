"""Independent counterexamples for byte mappings, bounded discovery and model parity."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_inference_a4 import parsed
from test_inference_engine import setup

from protocol_lab.framing.engine import FramingSpec, StreamInput
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.engine import (
    Meter,
    anchor,
    message_time_interval,
    propose_copied_values,
    propose_counters,
    propose_session_regions,
    propose_timestamps,
    typed_evaluation,
)
from protocol_lab.inference.models import ChecksumRule, CounterRule, TimestampRule
from protocol_lab.interpretation.checksums import REGISTRY, calculate
from protocol_lab.interpretation.document import load_model
from protocol_lab.research.action_logs import ActionEvent
from protocol_lab.validation.corpus import CorpusEvaluator
from protocol_lab.validation.engine import validate_stream


@pytest.mark.parametrize(
    "data,width,endian,signed,parameter,expected",
    [
        (b"\x01\x00", 2, "big", False, 1, "failed"),
        (b"\x01\x00", 1, "little", False, 1, "failed"),
        (b"\x01\x00", 2, "little", False, 1, "passed"),
        (b"\xff\xff", 2, "big", True, -1, "passed"),
        (b"\xfe\xff", 2, "big", True, -2, "failed"),
    ],
)
def test_integer_parameter_mapping_compares_exact_representation(
    data, width, endian, signed, parameter, expected
):
    check = dict(
        kind="parameter_mapping",
        name="mapping",
        field="value",
        parameter_path=["n"],
        encoding="integer",
        width=width,
        endian=endian,
        signed=signed,
    )
    fields = [dict(kind="int", name="value", width=2, endian="little", signed=signed)]
    model, items, run_id = parsed(data, [check], fields, size=2)
    event = ActionEvent(
        id=uuid4(),
        log_id=uuid4(),
        row_index=1,
        timestamp_ns="100",
        label="test",
        parameters_json='{"n":' + str(parameter) + "}",
    )
    evaluator = CorpusEvaluator(model, run_id, (event,))
    evaluator.add(items[0], (100, 100))
    assert [row.status for row in evaluator.finish()] == [expected]


def candidate_for(rule):
    return SimpleNamespace(id=uuid4(), rule=rule, scope=SimpleNamespace(direction="a_to_b"))


def check_candidate_and_model(rule, data, times, expected, ranges=None):
    snapshot, inputs = setup(data)
    item = inputs[0]
    if ranges is not None:
        item.source = StreamInput(len(data), ranges, lambda start, size: data[start : start + size])
    item.packet_times = times
    candidate = candidate_for(rule)
    base, metrics, evidence = typed_evaluation(
        snapshot, candidate, inputs, lambda: False, Meter(1000000)
    )
    assert base.complete
    model = load_model(model_draft(candidate).document_json)
    evaluator = CorpusEvaluator(model, uuid4())
    parsed_items = list(validate_stream(uuid4(), item.capture, item.stream, item.source, model))
    for row in parsed_items:
        evaluator.add(row, message_time_interval(item, row.anchor), item.source)
    results = list(evaluator.finish()) if model.corpus_checks else parsed_items
    assert [row.status for row in evidence] == expected
    assert [row.status for row in results] == expected
    assert metrics.matched == expected.count("passed")
    assert metrics.contradicted == expected.count("failed")
    assert metrics.unknown == expected.count("unknown")
    assert len(evidence) == len(results)


@pytest.mark.parametrize("drift", [100000, -100000])
@pytest.mark.parametrize("condition", ["valid", "contradiction", "missing_time", "backward_clock"])
def test_timestamp_drift_model_and_candidate_have_identical_outcomes(drift, condition):
    values = [1000000, 2000000, 3000000]
    stamps = [value + value * drift // 1000000 + 37 for value in values]
    expected = ["passed"] * 3
    if condition == "contradiction":
        stamps[1] += 50
        expected[1] = "failed"
    elif condition == "backward_clock":
        stamps[1] = 1
        expected[1] = "unknown"
    times = tuple(
        (i * 8, (i + 1) * 8, stamp)
        for i, stamp in enumerate(stamps)
        if condition != "missing_time" or i != 1
    )
    rule = TimestampRule(
        kind="timestamp_candidate",
        field=dict(offset=0, width=8, endian="little"),
        unit="ns",
        epoch="unix",
        clock_offset_ns="37",
        tolerance_ns=10,
        drift_ppm=drift,
        framing=dict(rule=dict(kind="fixed", size=8)),
    )
    if condition == "missing_time":
        expected[1] = "unknown"
    check_candidate_and_model(
        rule, b"".join(value.to_bytes(8, "little") for value in values), times, expected
    )


def test_relative_timestamp_uses_interval_uncertainty_drift_and_offset_in_both_paths():
    rule = TimestampRule(
        kind="relative_clock_candidate",
        field=dict(offset=0, width=8, endian="big"),
        unit="ns",
        epoch="session_relative",
        clock_offset_ns="2",
        tolerance_ns=0,
        drift_ppm=100000,
        framing=dict(rule=dict(kind="fixed", size=8)),
    )
    # Baseline uncertainty is [100,104]; the next interval is [113,117].
    # A predicted delta of 13 lies in [9,17], even though midpoint delta is 13.
    times = ((0, 8, 100), (0, 8, 104), (8, 16, 113), (8, 16, 117), (16, 24, 150))
    check_candidate_and_model(
        rule,
        b"".join(value.to_bytes(8, "big") for value in [10, 20, 30]),
        times,
        ["unknown", "passed", "failed"],
    )


@pytest.mark.parametrize("status", ["gap", "ambiguous"])
def test_counter_model_and_candidate_preserve_uncertain_transition_barriers(status):
    rule = CounterRule(
        kind="counter",
        field=dict(offset=0, width=1, endian="big"),
        framing=dict(rule=dict(kind="fixed", size=4)),
    )
    check_candidate_and_model(
        rule,
        b"\x00abc\x01abc\x02abc\x03abc",
        (),
        ["unknown", "unknown", "unknown", "passed"],
        ranges=[(0, 4, "known"), (4, 8, status), (8, 16, "known")],
    )


def test_counter_model_and_candidate_preserve_incomplete_final_message():
    rule = CounterRule(
        kind="counter",
        field=dict(offset=0, width=1, endian="big"),
        framing=dict(rule=dict(kind="fixed", size=4)),
    )
    check_candidate_and_model(rule, b"\x00abc\x01a", (), ["unknown", "unknown"])


@pytest.mark.parametrize("step", ["fixed", "message_length", "payload_length"])
@pytest.mark.parametrize("signed", [False, True])
def test_counter_model_and_candidate_agree_on_baseline_wrap_steps_and_counterexamples(step, signed):
    values = (
        ([126, 127, -128, -125] if signed else [254, 255, 0, 3])
        if step == "fixed"
        else [0, 4, 8, 13]
        if step == "message_length"
        else [0, 2, 4, 9]
    )
    rule = CounterRule(
        kind="counter",
        field=dict(offset=1, width=1, endian="big", signed=signed),
        step=step,
        framing=dict(rule=dict(kind="fixed", size=4)),
    )
    check_candidate_and_model(
        rule,
        b"".join(b"P" + value.to_bytes(1, "big", signed=signed) + b"xy" for value in values),
        (),
        ["unknown", "passed", "passed", "failed"],
    )


@pytest.mark.parametrize("algorithm", REGISTRY)
@pytest.mark.parametrize("endian", ["big", "little"])
def test_checksum_model_and_candidate_agree_on_coverage_and_corruption(algorithm, endian):
    width = REGISTRY[algorithm].width // 8
    records = []
    for i in range(3):
        body = b"P" + bytes([i]) + b"abc"
        value = calculate(algorithm, body[1:])
        if i == 1:
            value ^= 1
        records.append(body + value.to_bytes(width, endian))
    rule = ChecksumRule(
        kind="checksum_relation",
        algorithm=algorithm,
        field=dict(offset=0, width=width, endian=endian),
        field_relative_to="message_end",
        coverage="before_field",
        coverage_start=1,
        framing=dict(rule=dict(kind="fixed", size=5 + width)),
    )
    check_candidate_and_model(rule, b"".join(records), (), ["passed", "failed", "passed"])


@pytest.mark.parametrize("family", ["counters", "timestamps", "regions", "copies"])
def test_relational_discovery_enforces_remaining_evidence_budget(family):
    data = b"".join(bytes([i]) + b"abc" for i in range(4))
    if family == "timestamps":
        data = b"".join(i.to_bytes(4, "big") for i in range(4))
    elif family in {"regions", "copies"}:
        data = b"".join(i.to_bytes(4, "big") + b"AAAA" for i in range(4))
    snapshot, inputs = setup(data, data[:-1] + b"Z")
    size = 8 if family in {"regions", "copies"} else 4
    parent = SimpleNamespace(
        id=uuid4(),
        rule=SimpleNamespace(framing=FramingSpec(rule=dict(kind="fixed", size=size))),
        scope=SimpleNamespace(direction="a_to_b"),
    )
    if family == "regions":
        other = b"".join(i.to_bytes(4, "big") + b"BBBB" for i in range(4))
        inputs[1].source.read_bytes = lambda start, size: other[start : start + size]
    if family == "copies":
        inputs[1].stream = inputs[1].stream.model_copy(
            update={
                "session_id": inputs[0].stream.session_id,
                "direction": "b_to_a",
            }
        )
    messages = []
    for index, item in enumerate(inputs):
        item.packet_times = tuple(
            (start, start + size, (start // size) * 1000000000 + index * 1000)
            for start in range(0, len(data), size)
        )
        for start in range(0, len(data), size):
            messages.append(
                (item, anchor(item.stream, start, start + size), item.source.read(start, size))
            )
    meter = Meter(1, used=1)
    if family == "timestamps":
        messages = [message for message in messages if message[0] is inputs[0]]
        inputs = inputs[:1]
    with pytest.raises(ValueError, match="max_evidence_bytes"):
        if family == "copies":
            propose_copied_values(
                uuid4(),
                snapshot,
                parent,
                {
                    direction: [m for m in messages if m[0].stream.direction == direction]
                    for direction in ("a_to_b", "b_to_a")
                },
                (parent.id,),
                inputs,
                Meter(1000),
                meter,
                "a_to_b",
            )
        else:
            detector = {
                "counters": propose_counters,
                "timestamps": propose_timestamps,
                "regions": propose_session_regions,
            }[family]
            detector(uuid4(), snapshot, parent, messages, inputs, Meter(1000), meter)
    assert meter.used <= meter.maximum
