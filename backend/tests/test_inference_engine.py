"""Deterministic A1 searches on reconstructed byte streams, without packet boundaries."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.framing.engine import StreamInput
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.engine import StreamData, discover, evaluate
from protocol_lab.inference.models import CandidateInput, InferenceSnapshot, InferenceSpec
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
    spec = InferenceSpec.model_validate(
        dict(
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
            **updates,
        )
    )
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
    data = b"".join(b"\xaa\xbb"+(8+i).to_bytes(2, "little")+i.to_bytes(4, "little")
                    +hashlib.shake_256(str(i).encode()).digest(4+i) for i in range(96))
    snapshot, inputs = setup(data)
    _, candidates, _ = discover(snapshot, inputs)
    top = [c for c in candidates if c.family == "framing"][:5]
    assert any(c.rule.kind == "length_framing" and c.rule.framing.rule.offset == 2
               and c.rule.framing.rule.width == 2 and c.rule.framing.rule.endian == "little"
               and c.rule.framing.rule.adjustment == 4 for c in top)


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
    assert all("semantics" in " ".join(c.limitations) for c in candidates)
    assert run.coverage.stream_bytes == len(inputs[0].source.read_bytes(0, inputs[0].stream.extent))


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
    assert main(["infer", "--capture", str(path), "--spec", str(spec_path), "--output", str(repeated)]) == 0
    assert json.loads(repeated.read_text())["result"]["semantic_sha256"] == body["result"]["semantic_sha256"]
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
