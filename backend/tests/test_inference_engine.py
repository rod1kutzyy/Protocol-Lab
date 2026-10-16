"""Deterministic A1 searches on reconstructed byte streams, without packet boundaries."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.framing.engine import StreamInput
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.engine import StreamData, discover, evaluate
from protocol_lab.inference.models import (
    CandidateInput,
    FrozenEventInput,
    InferenceSnapshot,
    InferenceSpec,
)
from protocol_lab.storage.inference import versions
from protocol_lab.validation.models import CaptureSnapshot, StoredCorpus


def setup(data, holdout=None, **updates):
    project, corpus = UUID(int=1), UUID(int=2)
    sources, inputs = [], []
    for n, payload in enumerate([data] + ([] if holdout is None else [holdout]), 10):
        capture = CaptureSnapshot(
            id=UUID(int=n),
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            packet_count=1,
            eligible_packets=1,
            checksum_policy="warn",
            import_settings={},
            import_engine_version="test",
            diagnostics={},
            reconstruction_id=UUID(int=n + 10),
            reconstruction_sha256=None,
            reconstruction_settings={},
            reconstruction_engine_version="tcp-test",
            streams=(
                dict(
                    id=UUID(int=n + 100),
                    session_id=UUID(int=n + 200),
                    reconstruction_version="tcp-test",
                    reconstruction_policy="retain-all",
                    extent=len(payload),
                    direction="a_to_b",
                    included=True,
                    data_status_bytes={"known": len(payload)},
                ),
            ),
        )
        sources.append(capture)
        inputs.append(
            StreamData(
                capture,
                capture.streams[0],
                StreamInput(
                    len(payload),
                    [(0, len(payload), "known")],
                    lambda start, size, payload=payload: payload[start : start + size],
                ),
            )
        )
    config = dict(
        corpus_version_id=corpus,
        detectors=[dict(family="framing"), dict(family="structure"), dict(family="entropy")],
        split=dict(
            discovery_ids=[sources[0].id],
            holdout_ids=[s.id for s in sources[1:]],
            holdout_unavailable_reason="One recording" if holdout is None else None,
        ),
        search=dict(
            fixed_size_max=64,
            adjustment_min=-8,
            adjustment_max=8,
            marker_max_bytes=4,
            max_marker_patterns=8,
        ),
        budget=dict(max_header_bytes=8, max_rule_trials=5000, max_framing_alternatives=10),
    )
    config.update(updates)
    spec = InferenceSpec.model_validate(config)
    snapshot = InferenceSnapshot(
        project_id=project,
        spec=spec,
        corpus=StoredCorpus(
            id=corpus,
            corpus_id=UUID(int=3),
            project_id=project,
            name="Synthetic A1",
            spec=dict(capture_ids=[s.id for s in sources]),
            sha256="0" * 64,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        sources=tuple(sources),
        engines=versions(),
    )
    return snapshot, inputs


def length_data(endian="little", sizes=(3, 7, 4, 9, 5, 11)):
    return b"".join(
        b"\xaa\xbb" + n.to_bytes(2, endian) + bytes([65 + i]) * n for i, n in enumerate(sizes)
    )


@pytest.mark.parametrize("endian", ["big", "little"])
def test_length_candidates_markers_and_determinism(endian):
    snapshot, inputs = setup(length_data(endian), length_data(endian, (13, 8, 6)))

    def forbidden(*args):
        raise AssertionError("Discovery read holdout")

    inputs[1].source.read_bytes = forbidden
    run, candidates, evidence = discover(snapshot, inputs)
    lengths = [c for c in candidates if c.rule.kind == "length_framing"]
    assert any(
        c.rule.framing.rule.offset == 2
        and c.rule.framing.rule.width == 2
        and c.rule.framing.rule.endian == endian
        and c.rule.framing.rule.adjustment == 4
        for c in lengths
    ), [(c.rule, c.metrics) for c in lengths]
    assert any(c.rule.kind == "start_marker" for c in candidates)
    assert any(c.rule.kind == "entropy_region" for c in candidates)
    assert run.rule_trials <= snapshot.spec.budget.max_rule_trials
    assert all(e.anchor.stream_id == inputs[0].stream.id for e in evidence)
    other, other_candidates, _ = discover(snapshot, list(reversed(inputs)))
    assert run.semantic_sha256 == other.semantic_sha256
    assert [(c.rule_sha256, c.metrics) for c in candidates] == [
        (c.rule_sha256, c.metrics) for c in other_candidates
    ]
    assert model_draft(lengths[0]).compilable


def test_variable_random_payloads_do_not_promote_a_few_large_blocks_over_a_chain():
    data = b"".join(
        b"\xaa\xbb"
        + (8 + i).to_bytes(2, "little")
        + i.to_bytes(4, "little")
        + hashlib.shake_256(str(i).encode()).digest(4 + i)
        for i in range(96)
    )
    snapshot, inputs = setup(data)
    _, candidates, _ = discover(snapshot, inputs)
    top = [c for c in candidates if c.family == "framing"][:5]
    assert any(
        c.rule.kind == "length_framing"
        and c.rule.framing.rule.offset == 2
        and c.rule.framing.rule.width == 2
        and c.rule.framing.rule.endian == "little"
        and c.rule.framing.rule.adjustment == 4
        for c in top
    )


def test_fixed_and_marker_candidates_and_no_semantic_claim():
    snapshot, inputs = setup(
        b"".join(b"\xaa\xbb" + bytes([65 + i]) * 4 + b"\xcc\xdd" for i in range(8))
    )
    run, candidates, evidence = discover(snapshot, inputs)
    assert any(c.rule.kind == "fixed_framing" and c.rule.framing.rule.size == 8 for c in candidates)
    assert any(
        c.rule.kind == "marker_framing"
        and c.rule.framing.rule.start_hex == "aabb"
        and c.rule.framing.rule.end_hex == "ccdd"
        for c in candidates
        if c.family == "framing"
    )
    assert run.coverage.stream_bytes == len(inputs[0].source.read_bytes(0, inputs[0].stream.extent))


def test_a2_delimiter_and_repeated_opcode_groups_are_proposed_with_evidence():
    payload = b"ab|cd|e" + b"xy|zq|r" + b"mn|op|q" + b"uv|wx|y"
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="framing"), dict(family="structure"), dict(family="groups")],
        search=dict(fixed_size_min=7, fixed_size_max=7, adjustment_min=0, adjustment_max=0),
    )
    _, candidates, evidence = discover(snapshot, inputs)
    delimiters = [c for c in candidates if c.rule.kind == "field_delimiter"]
    assert any(c.rule.delimiter_hex == "7c" for c in delimiters)
    assert any(c.family == "structure" and c.dependency_ids for c in delimiters)
    group_payload = b"".join(
        bytes([opcode, index, 65 + index, 66 + index])
        for opcode in (1, 2, 3)
        for index in range(1, 4)
    )
    snapshot, inputs = setup(
        group_payload,
        detectors=[dict(family="framing"), dict(family="groups")],
        search=dict(fixed_size_min=4, fixed_size_max=4, adjustment_min=0, adjustment_max=0),
    )
    _, candidates, evidence = discover(snapshot, inputs)
    opcodes = [c for c in candidates if c.rule.kind == "opcode_candidate"]
    assert opcodes
    assert len({candidate.id for candidate in candidates}) == len(candidates)
    assert any(c.rule.key_fields[0].offset == 0 and c.metrics.matched >= 6 for c in opcodes)
    assert any(e.candidate_id == opcodes[0].id and e.anchor is not None for e in evidence)


def test_a2_event_windows_preserve_unknown_and_overlapping_ambiguity():
    payload = b"".join(bytes([1, index, 65, 66]) for index in range(1, 7))
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="framing"), dict(family="events")],
        event_before_ns=100,
        event_after_ns=100,
        search=dict(fixed_size_min=4, fixed_size_max=4, adjustment_min=0, adjustment_max=0),
    )
    inputs[0].packet_times = ((0, 12, 1000), (12, len(payload), 10000))
    log_id = UUID(int=900)
    spec = InferenceSpec.model_validate(
        {
            **snapshot.spec.model_dump(),
            "logs": [
                {
                    "log_id": log_id,
                    "sha256": "a" * 64,
                    "clock_revision": 1,
                    "clock_offset_ns": "0",
                    "timestamp_field": "time",
                    "label_field": "action",
                    "timestamp_format": "unix_ns",
                    "format": "json",
                },
            ],
        }
    )
    snapshot = snapshot.model_copy(
        update={
            "spec": spec,
            "events": (
                FrozenEventInput(
                    id=UUID(int=901),
                    log_id=log_id,
                    timestamp_ns="1000",
                    label="one",
                    parameters_json="{}",
                ),
                FrozenEventInput(
                    id=UUID(int=902),
                    log_id=log_id,
                    timestamp_ns="1050",
                    label="two",
                    parameters_json="{}",
                ),
                FrozenEventInput(
                    id=UUID(int=903),
                    log_id=log_id,
                    timestamp_ns="10000",
                    label="three",
                    parameters_json="{}",
                ),
                FrozenEventInput(
                    id=UUID(int=904),
                    log_id=log_id,
                    timestamp_ns="50000",
                    label="four",
                    parameters_json="{}",
                ),
            ),
        }
    )
    _, candidates, evidence = discover(snapshot, inputs)
    candidate = next(c for c in candidates if c.family == "events")
    assert (
        candidate.metrics.matched == 1
        and candidate.metrics.ambiguous == 2
        and candidate.metrics.unknown == 1
    )
    assert {e.event_id for e in evidence if e.candidate_id == candidate.id} == {
        UUID(int=901),
        UUID(int=902),
        UUID(int=903),
        UUID(int=904),
    }


def test_a2_parameter_mapping_searches_only_declared_values_in_known_stream_bytes():
    payload = b"prefix-alpha-middle-beta-suffix"
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="data_mapping")],
        parameters=[{"text": "alpha"}, {"text": "beta"}],
    )
    _, candidates, evidence = discover(snapshot, inputs)
    mappings = [c for c in candidates if c.family == "data_mapping"]
    assert any(c.rule.encoding in {"ascii", "utf-8"} for c in mappings)
    assert all(
        e.status == "passed" and e.anchor is not None
        for c in mappings
        for e in evidence
        if e.candidate_id == c.id
    )


def test_a2_parameter_mapping_matches_values_across_internal_scan_chunks():
    payload = b"x" * 65534 + b"alpha" + b"y" * 65534 + b"beta"
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="data_mapping")],
        parameters=[{"text": "alpha"}, {"text": "beta"}],
    )
    _, candidates, evidence = discover(snapshot, inputs)
    candidate = next(
        c for c in candidates if c.family == "data_mapping" and c.rule.encoding == "ascii"
    )
    starts = {
        e.anchor.byte_range.start
        for e in evidence
        if e.candidate_id == candidate.id and e.anchor is not None
    }
    assert {65534, 131073} <= starts


def test_a2_parameter_mapping_checks_numeric_text_and_integer_widths():
    log_id, first, second = UUID(int=910), UUID(int=911), UUID(int=912)
    payload = b"prefix" + (640).to_bytes(2, "little") + b"middle" + (960).to_bytes(2, "little")
    snapshot, inputs = setup(payload, detectors=[dict(family="data_mapping")])
    spec = InferenceSpec.model_validate(
        {
            **snapshot.spec.model_dump(),
            "logs": [
                {
                    "log_id": log_id,
                    "sha256": "b" * 64,
                    "clock_revision": 1,
                    "clock_offset_ns": "0",
                    "timestamp_field": "time",
                    "label_field": "action",
                    "timestamp_format": "unix_ns",
                    "format": "json",
                }
            ],
            "parameters": [
                {"log_id": log_id, "event_ids": [first, second], "parameter_path": ["speed"]}
            ],
        }
    )
    snapshot = snapshot.model_copy(
        update={
            "spec": spec,
            "events": (
                FrozenEventInput(
                    id=first,
                    log_id=log_id,
                    timestamp_ns="1000",
                    label="set speed",
                    parameters_json='{"speed":640}',
                ),
                FrozenEventInput(
                    id=second,
                    log_id=log_id,
                    timestamp_ns="2000",
                    label="set speed",
                    parameters_json='{"speed":960}',
                ),
            ),
        }
    )
    _, candidates, evidence = discover(snapshot, inputs)
    integer_rule = next(
        c
        for c in candidates
        if c.family == "data_mapping"
        and c.rule.encoding == "integer"
        and c.rule.integer.width == 2
        and c.rule.integer.endian == "little"
    )
    assert integer_rule.metrics.matched == 2
    assert len([e for e in evidence if e.candidate_id == integer_rule.id]) >= 2


def test_rule_trial_budget_is_shared_across_directions():
    from protocol_lab.inference.engine import StreamData

    snapshot, inputs = setup(length_data())
    budget = snapshot.spec.budget.model_copy(update={"max_rule_trials": 1})
    snapshot = snapshot.model_copy(
        update={"spec": snapshot.spec.model_copy(update={"budget": budget})}
    )
    original = inputs[0]
    reverse = original.stream.model_copy(
        update={"id": UUID(int=999), "session_id": UUID(int=998), "direction": "b_to_a"}
    )
    capture = original.capture.model_copy(update={"streams": (*original.capture.streams, reverse)})
    snapshot = snapshot.model_copy(update={"sources": (capture,)})
    forward = StreamData(capture, original.stream, original.source)
    backward = StreamData(
        capture,
        reverse,
        StreamInput(
            reverse.extent,
            [(0, reverse.extent, "known")],
            original.source.read_bytes,
        ),
    )

    run, _, _ = discover(snapshot, [forward, backward])

    assert run.rule_trials <= snapshot.spec.budget.max_rule_trials


def test_frozen_rule_holdout_bad_lengths_and_cancel():
    snapshot, inputs = setup(length_data(), length_data(sizes=(17, 6, 15)) + b"\xaa\xbb\x00")
    _, candidates, _ = discover(snapshot, inputs)
    candidate = next(c for c in candidates if c.rule.kind == "length_framing")
    evaluation_snapshot = snapshot.model_copy(
        update={
            "spec": snapshot.spec.model_copy(
                update={"mode": "evaluate", "candidate_ids": (candidate.id,)}
            ),
            "candidates": (
                CandidateInput(id=candidate.id, sha256=candidate.rule_sha256, rule=candidate.rule),
            ),
        }
    )
    record, evidence = evaluate(evaluation_snapshot, candidate, inputs[1:], candidate.run_id)
    assert record.evaluation.rule_sha256 == candidate.rule_sha256
    assert record.evaluation.metrics.unknown > 0
    assert all(e.anchor.stream_id == inputs[1].stream.id for e in evidence)
    with pytest.raises(WorkCancelled):
        discover(snapshot, inputs, cancelled=lambda: True)


def test_random_or_repeated_one_message_has_no_supported_candidates():
    snapshot, inputs = setup(hashlib.shake_256(b"deterministic noise").digest(256))
    _, candidates, _ = discover(snapshot, inputs)
    assert all(c.compiler_support != "confirmed" for c in candidates)
    assert all("semantics" in " ".join(c.limitations) for c in candidates)
    snapshot, inputs = setup(b"\xaa\xbb1234" * 8)
    _, candidates, _ = discover(snapshot, inputs)
    # Submessage explanations may exist; identical messages never imply independent support.
    assert all(
        c.metrics.unique_messages >= snapshot.spec.search.min_unique_messages
        for c in candidates
        if c.family == "framing"
    )


def test_gap_and_ambiguous_bytes_are_not_contradictions_and_no_resync():
    from protocol_lab.framing.engine import FramingSpec, LengthRule
    from protocol_lab.inference.engine import Meter, check_framing

    data = length_data()
    snapshot, inputs = setup(data)
    inputs[0].source = StreamInput(
        len(data),
        [(0, 2, "known"), (2, 4, "gap"), (4, len(data), "known")],
        lambda a, n: data[a : a + n],
    )
    rule = FramingSpec(
        rule=LengthRule(kind="length", offset=2, width=2, endian="little", adjustment=4)
    )
    result = check_framing(
        snapshot, UUID(int=300), rule, inputs, lambda: False, Meter(10000), Meter(1000)
    )
    assert not result.messages
    assert [e.status for e in result.evidence] == ["unknown"]
    assert result.evidence[0].anchor.byte_range.end == len(data)
    inputs[0].source = StreamInput(len(data), [(0, len(data), "ambiguous")], lambda *_: b"")
    result = check_framing(
        snapshot, UUID(int=300), rule, inputs, lambda: False, Meter(10000), Meter(1000)
    )
    assert [e.status for e in result.evidence] == ["ambiguous"]


def test_technical_limits_remain_unknown_and_publish_no_partial_pass():
    from protocol_lab.framing.engine import FramingSpec, LengthRule
    from protocol_lab.inference.engine import Meter, check_framing

    snapshot, inputs = setup(length_data())
    rule = FramingSpec(
        rule=LengthRule(kind="length", offset=2, width=2, endian="little", adjustment=4),
        max_message_bytes=5,
    )
    result = check_framing(
        snapshot, UUID(int=300), rule, inputs, lambda: False, Meter(10000), Meter(1000)
    )
    assert all(e.status == "unknown" for e in result.evidence)
    rule = rule.model_copy(update={"max_message_bytes": 1000})
    limited = check_framing(
        snapshot, UUID(int=300), rule, inputs, lambda: False, Meter(1), Meter(1000)
    )
    assert not limited.complete and not limited.messages
    assert all(e.status == "unknown" for e in limited.evidence)


def test_output_budget_is_a_failed_operation_not_a_protocol_counterexample():
    snapshot, inputs = setup(length_data())
    snapshot = snapshot.model_copy(
        update={
            "spec": snapshot.spec.model_copy(
                update={
                    "budget": snapshot.spec.budget.model_copy(update={"max_evidence_bytes": 16}),
                }
            )
        }
    )
    with pytest.raises(ValueError, match="max_evidence_bytes"):
        discover(snapshot, inputs)


def test_resegmented_recording_is_not_independent_and_limits_are_unknown():
    from protocol_lab.inference.independence import recording_overlap

    snapshot, inputs = setup(
        length_data(sizes=(33, 44, 55)), length_data(sizes=(33, 44, 55)) + b"X"
    )
    for item in inputs:
        item.wire_identity = ("192.0.2.1", 4000, "192.0.2.2", 5000)
        item.sequence_origin = 100
    assert recording_overlap(inputs[:1], inputs[1:], snapshot.spec.budget)[0] == "exploratory"
    limited = snapshot.spec.budget.model_copy(update={"max_scanned_bytes": 1})
    assert recording_overlap(inputs[:1], inputs[1:], limited)[0] == "unverified"


def test_cli_infer_and_fixed_candidate_reuse_are_offline_and_exclusive(tmp_path):
    import json
    from pathlib import Path
    from uuid import NAMESPACE_URL, uuid5

    from protocol_lab.capture.index import sha256_file
    from protocol_lab.cli.main import main

    fixtures = Path(__file__).resolve().parents[2] / "tests/fixtures/inference"
    path = fixtures / "length-discovery.pcap"
    capture_id = uuid5(NAMESPACE_URL, f"protocol-lab:capture:{sha256_file(path)}")
    spec_path = tmp_path / "spec.json"
    configured = dict(
        corpus_version_id=str(UUID(int=900)),
        detectors=[dict(family="framing")],
        split=dict(discovery_ids=[str(capture_id)], holdout_unavailable_reason="First file"),
        budget=dict(max_header_bytes=8, max_rule_trials=5000),
        search=dict(
            fixed_size_max=64,
            adjustment_min=-8,
            adjustment_max=8,
            marker_max_bytes=4,
            max_marker_patterns=8,
        ),
    )
    spec_path.write_text(json.dumps(configured))
    output = tmp_path / "discovery.json"
    assert (
        main(["infer", "--capture", str(path), "--spec", str(spec_path), "--output", str(output)])
        == 0
    )
    body = json.loads(output.read_text())
    repeated = tmp_path / "repeated.json"
    assert (
        main(["infer", "--capture", str(path), "--spec", str(spec_path), "--output", str(repeated)])
        == 0
    )
    assert (
        json.loads(repeated.read_text())["result"]["semantic_sha256"]
        == body["result"]["semantic_sha256"]
    )
    candidate = next(c for c in body["candidates"] if c["rule"]["kind"] == "length_framing")
    document = tmp_path / "candidate.json"
    document.write_text(json.dumps(candidate))
    target = tmp_path / "evaluation.json"
    assert (
        main(
            [
                "evaluate-candidate",
                "--capture",
                str(fixtures / "length-holdout.pcap"),
                "--candidate",
                str(document),
                "--output",
                str(target),
            ]
        )
        == 0
    )
    evaluated = json.loads(target.read_text())["result"]
    assert evaluated["evaluation"]["rule_sha256"] == candidate["rule_sha256"]
    assert evaluated["evaluation"]["metrics"]["matched"] >= 3
    before = output.read_bytes()
    assert (
        main(["infer", "--capture", str(path), "--spec", str(spec_path), "--output", str(output)])
        == 2
    )
    assert output.read_bytes() == before


def _evaluation_snapshot(snapshot, candidate):
    spec = snapshot.spec.model_copy(update={"mode": "evaluate", "candidate_ids": (candidate.id,)})
    return InferenceSnapshot(
        project_id=snapshot.project_id,
        spec=spec,
        corpus=snapshot.corpus,
        sources=snapshot.sources,
        candidates=(
            CandidateInput(id=candidate.id, sha256=candidate.rule_sha256, rule=candidate.rule),
        ),
        engines=snapshot.engines,
    )


def test_a3_counter_wrap_candidate_executes_as_a_frozen_typed_rule():
    payload = b"".join(bytes([value]) + b"xyz" for value in (254, 255, 0, 1, 2, 3))
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="framing"), dict(family="counters")],
        search=dict(
            fixed_size_min=4,
            fixed_size_max=4,
            adjustment_min=0,
            adjustment_max=0,
            marker_max_bytes=2,
        ),
        budget=dict(max_header_bytes=4, max_rule_trials=500),
    )
    run, candidates, _ = discover(snapshot, inputs)
    candidate = next(
        c
        for c in candidates
        if c.rule.kind == "counter"
        and c.rule.field.offset == 0
        and c.rule.field.width == 1
        and c.rule.step == "fixed"
        and c.rule.increment == 1
    )
    assert candidate.metrics.matched >= 2
    assert candidate.rule.framing.rule.size == 4

    result, facts = evaluate(_evaluation_snapshot(snapshot, candidate), candidate, inputs, run.id)
    assert result.evaluation.metrics.matched == 5
    assert result.evaluation.metrics.contradicted == 0
    assert all(fact.status == "passed" for fact in facts)


def test_a3_timestamp_candidate_uses_packet_intervals_and_one_shared_offset():
    epoch_ns = 1_700_000_000_000_000_000
    seconds = 1_700_000_000
    payload = b"".join((seconds + i).to_bytes(4, "little") + b"ABCD" for i in range(5))
    snapshot, inputs = setup(
        payload,
        detectors=[dict(family="framing"), dict(family="timestamps")],
        search=dict(
            fixed_size_min=8,
            fixed_size_max=8,
            adjustment_min=0,
            adjustment_max=0,
            marker_max_bytes=2,
        ),
        budget=dict(max_header_bytes=8, max_rule_trials=1000),
    )
    inputs[0].packet_times = tuple(
        (i * 8, (i + 1) * 8, epoch_ns + i * 1_000_000_000) for i in range(5)
    )
    run, candidates, _ = discover(snapshot, inputs)
    candidate = next(
        c
        for c in candidates
        if c.rule.kind == "timestamp_candidate"
        and c.rule.field.offset == 0
        and c.rule.field.width == 4
        and c.rule.unit == "s"
    )
    assert int(candidate.rule.clock_offset_ns) == 0
    assert candidate.metrics.matched == 5

    result, facts = evaluate(_evaluation_snapshot(snapshot, candidate), candidate, inputs, run.id)
    assert result.evaluation.metrics.matched == 5
    assert result.evaluation.metrics.contradicted == 0
    assert all(fact.status == "passed" for fact in facts)


def test_a3_session_stable_region_requires_multiple_observed_sessions():
    def session(token):
        return b"".join(bytes([i]) + token + b"xyz" for i in range(5))

    snapshot, inputs = setup(
        session(b"AAAA"),
        session(b"BBBB"),
        detectors=[dict(family="framing"), dict(family="tokens")],
        split=dict(
            discovery_ids=[UUID(int=10), UUID(int=11)],
            holdout_ids=[],
            holdout_unavailable_reason="No independent holdout recording",
        ),
        search=dict(
            fixed_size_min=8,
            fixed_size_max=8,
            adjustment_min=0,
            adjustment_max=0,
            marker_max_bytes=2,
        ),
        budget=dict(max_header_bytes=8, max_rule_trials=1000),
    )
    _, candidates, _ = discover(snapshot, inputs)
    assert any(
        c.rule.kind == "session_stable_region"
        and c.rule.offset == 1
        and c.rule.length == 4
        and c.metrics.sessions == 2
        for c in candidates
    )


def test_a3_exact_reverse_copy_is_proposed_and_evaluated_with_source_anchors():
    from protocol_lab.inference.engine import StreamData

    source_data = b"".join(i.to_bytes(4, "little") + b"abcd" for i in range(1, 6))
    target_data = b"".join(b"X" + i.to_bytes(4, "little") + b"ZAA" for i in range(1, 6))
    snapshot, original_inputs = setup(
        source_data,
        detectors=[dict(family="framing"), dict(family="tokens")],
        search=dict(
            fixed_size_min=8,
            fixed_size_max=8,
            adjustment_min=0,
            adjustment_max=0,
            marker_max_bytes=2,
        ),
        budget=dict(max_header_bytes=8, max_rule_trials=2000),
    )
    first = original_inputs[0]
    reverse_stream = first.stream.model_copy(update={"id": UUID(int=999), "direction": "b_to_a"})
    capture = first.capture.model_copy(update={"streams": (first.stream, reverse_stream)})
    original_inputs[0].capture = capture
    reverse = StreamData(
        capture,
        reverse_stream,
        StreamInput(
            len(target_data),
            [(0, len(target_data), "known")],
            lambda start, size: target_data[start : start + size],
        ),
        packet_times=tuple((i * 8, (i + 1) * 8, 2_000 + i * 2) for i in range(5)),
    )
    original_inputs[0].packet_times = tuple((i * 8, (i + 1) * 8, 1_000 + i * 2) for i in range(5))
    inputs = [original_inputs[0], reverse]
    snapshot = InferenceSnapshot(
        project_id=snapshot.project_id,
        spec=snapshot.spec,
        corpus=snapshot.corpus,
        sources=(capture,),
        engines=snapshot.engines,
    )
    run, candidates, _ = discover(snapshot, inputs)
    candidate = next(
        c
        for c in candidates
        if c.rule.kind == "copied_value"
        and c.rule.source_direction == "a_to_b"
        and c.rule.source_offset == 0
        and c.rule.target_offset == 1
        and c.rule.length == 4
    )
    assert candidate.metrics.distinct_values >= 2
    assert any(fact.status == "passed" and fact.anchor is not None for fact in _)

    result, facts = evaluate(_evaluation_snapshot(snapshot, candidate), candidate, inputs, run.id)
    assert result.evaluation.metrics.matched == 5
    assert result.evaluation.metrics.contradicted == 0
    assert all(fact.anchor is not None for fact in facts)
