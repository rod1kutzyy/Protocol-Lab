"""A4 checks independent registry vectors, real captures, DSL and shared corpus execution."""

import binascii
import hashlib
import io
import json
import zlib
from pathlib import Path
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from pydantic import ValidationError

from protocol_lab.capture.index import sha256_file
from protocol_lab.framing.engine import StreamInput
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.models import InferenceCandidate
from protocol_lab.interpretation.checksums import REGISTRY, calculate
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.schema import ProtocolModel, canonical, content_hash
from protocol_lab.research.action_logs import ActionEvent
from protocol_lab.services.application import apply_capture
from protocol_lab.services.inference_files import infer_files
from protocol_lab.validation.corpus import CorpusEvaluator
from protocol_lab.validation.engine import CoverageCounter, validate_stream
from protocol_lab.validation.models import StreamSnapshot

FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/inference"


@pytest.mark.parametrize("algorithm", list(REGISTRY))
def test_registry_known_independent_check_vectors(algorithm):
    assert calculate(algorithm, b"123456789") == REGISTRY[algorithm].check


def test_crc_references_and_odd_internet_checksum():
    for length in (0, 1, 2, 3, 64, 257, 1025):
        payload = hashlib.shake_256(str(length).encode()).digest(length)
        assert calculate("CRC-32/ISO-HDLC", payload) == zlib.crc32(payload) & 0xFFFFFFFF
        assert calculate("CRC-16/IBM-3740", payload) == binascii.crc_hqx(payload, 0xFFFF)
    assert calculate("internet_checksum", b"\x00\x01\x02") == 0xFDFE


def parsed(data, corpus_checks=(), fields=None, **updates):
    fields = fields or [
        dict(kind="int", name="value", width=1, signed=False, endian="big"),
        dict(kind="bytes", name="payload", length="remaining"),
    ]
    model = ProtocolModel.model_validate(
        dict(
            schema_version="interpretation-2",
            name="A4 tests",
            framing=dict(rule=dict(kind="fixed", size=updates.pop("size", 4))),
            fields=fields,
            corpus_checks=corpus_checks,
            **updates,
        )
    )
    stream = StreamSnapshot(
        id=uuid4(),
        session_id=uuid4(),
        reconstruction_version="test",
        reconstruction_policy="test",
        extent=len(data),
        direction="a_to_b",
        included=True,
    )
    capture = SimpleNamespace(id=uuid4(), sha256="0" * 64)
    source = StreamInput(len(data), [(0, len(data), "known")], lambda a, n: data[a : a + n])
    run_id = uuid4()
    return model, list(validate_stream(run_id, capture, stream, source, model)), run_id


def test_checksum_dsl_preserves_decoded_facts_on_failure_and_resource_unknown():
    body = b"123456789"
    data = body + zlib.crc32(body).to_bytes(4, "little")
    fields = [
        dict(kind="bytes", name="body", length=dict(remaining_minus=4)),
        dict(kind="int", name="crc", width=4, signed=False, endian="little"),
    ]
    check = dict(kind="checksum", field="crc", algorithm="CRC-32/ISO-HDLC", byte_order="little")
    model, items, _ = parsed(data, size=len(data), fields=fields, checks=[check])
    assert items[0].status == "passed"
    _, broken, _ = parsed(
        data[:-1] + bytes([data[-1] ^ 1]), size=len(data), fields=fields, checks=[check]
    )
    assert broken[0].status == "failed" and len(broken[0].fields) == 2
    _, limited, _ = parsed(
        data, size=len(data), fields=fields, checks=[check], max_checksum_bytes=1
    )
    assert (
        limited[0].status == "unknown" and limited[0].technical_limit.name == "max_checksum_bytes"
    )
    with pytest.raises(ValidationError, match="interpretation-2"):
        ProtocolModel.model_validate({**model.model_dump(), "schema_version": "interpretation-1"})


def test_legacy_content_hash_is_stable_after_additive_v2_defaults():
    model = load_model(
        (Path(__file__).resolve().parents[2] / "tests/fixtures/cli/length-model.json").read_text()
    )
    old = model.model_dump(mode="json")
    for key in (
        "direction",
        "corpus_checks",
        "max_corpus_units",
        "max_corpus_bytes",
        "max_checksum_bytes",
    ):
        old.pop(key)
    expected = hashlib.sha256(
        json.dumps(old, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert content_hash(model) == expected
    assert load_model(canonical(model)) == model


def test_corpus_counter_wrap_failure_and_unit_limits_do_not_double_count_bytes():
    checks = [dict(kind="counter", name="sequence", field="value")]
    model, items, run_id = parsed(b"\xfeabc\xffabc\x00abc\x03abc", checks)
    evaluator = CorpusEvaluator(model, run_id)
    snapshot = SimpleNamespace(sources=())
    counter = CoverageCounter(snapshot)
    for item in items:
        evaluator.add(item)
        counter.add(item)
    facts = list(evaluator.finish())
    assert [fact.status for fact in facts] == ["unknown", "passed", "passed", "failed"]
    before = sum(counter.bytes.values())
    for fact in facts:
        counter.add(fact)
    assert sum(counter.bytes.values()) == before == 16
    assert counter.relations["failed"] == 1
    limited = CorpusEvaluator(model.model_copy(update={"max_corpus_units": 1}), run_id)
    for item in items:
        limited.add(item)
    assert any(f.technical_limit and f.status == "unknown" for f in limited.finish())


def test_event_and_parameter_prerequisites_and_missing_events_are_explicit():
    checks = [
        dict(kind="event_association", name="action", after_ns=10),
        dict(
            kind="parameter_mapping",
            name="parameter",
            field="payload",
            parameter_path=["text"],
            encoding="utf-8",
        ),
    ]
    model, items, run_id = parsed(b"\x01abc", checks)
    missing = CorpusEvaluator(model, run_id)
    missing.add(items[0], (100, 100))
    assert all(f.status == "unknown" for f in missing.finish())
    event = ActionEvent(
        id=uuid4(),
        log_id=uuid4(),
        row_index=1,
        timestamp_ns="100",
        label="unrelated human label",
        parameters_json='{"text":"abc"}',
    )
    evaluator = CorpusEvaluator(model, run_id, (event,))
    evaluator.add(items[0], (100, 100))
    assert all(f.status == "passed" for f in evaluator.finish())
    overlap = CorpusEvaluator(model, run_id, (event, event.model_copy(update={"id": uuid4()})))
    overlap.add(items[0], (100, 100))
    assert all(f.status == "ambiguous" for f in overlap.finish())


def test_copied_value_compares_original_bytes_and_retains_both_anchors():
    checks = [
        dict(
            kind="copied_value",
            name="copy",
            source_field="left",
            target_field="right",
            source_direction="a_to_b",
        )
    ]
    fields = [
        dict(kind="int", name="left", width=2, signed=False, endian="little"),
        dict(kind="int", name="right", width=2, signed=False, endian="big"),
    ]
    model, source, run_id = parsed(b"\x01\x00\x00\x00", checks, fields)
    _, target, _ = parsed(b"\x00\x00\x00\x01", checks, fields)
    target = target[0].model_copy(
        update={"session_id": source[0].session_id, "direction": "b_to_a"}
    )
    evaluator = CorpusEvaluator(model, run_id)
    evaluator.add(source[0], (10, 10))
    evaluator.add(target, (20, 20))
    assert any(f.status == "failed" for f in evaluator.finish())  # Equal int, different bytes.
    _, equal_bytes, _ = parsed(b"\x00\x00\x01\x00", checks, fields)
    equal_bytes = equal_bytes[0].model_copy(
        update={"session_id": source[0].session_id, "direction": "b_to_a"}
    )
    evaluator = CorpusEvaluator(model, run_id)
    evaluator.add(source[0], (10, 10))
    evaluator.add(equal_bytes, (20, 20))
    facts = list(evaluator.finish())
    assert any(f.status == "passed" and f.related_anchors for f in facts)
    simultaneous = CorpusEvaluator(model, run_id)
    simultaneous.add(source[0], (10, 10))
    simultaneous.add(equal_bytes, (10, 10))
    assert any(f.status == "ambiguous" for f in simultaneous.finish())


def test_timestamp_exact_ns_drift_reference_and_nonmonotonic_capture_clock():
    epoch = 1_700_000_000_000_000_000
    checks = [
        dict(
            kind="timestamp",
            name="time",
            field="value",
            unit="ns",
            epoch="unix",
            reference_ns=str(epoch),
            drift_ppm=100,
            clock_offset_ns="37",
        )
    ]
    fields = [dict(kind="int", name="value", width=8, signed=False, endian="little")]
    data = b"".join((epoch + i * 10**9).to_bytes(8, "little") for i in range(3))
    model, items, run_id = parsed(data, checks, fields, size=8)
    evaluator = CorpusEvaluator(model, run_id)
    for index, item in enumerate(items):
        timestamp = epoch + index * 1_000_100_000 + 37
        evaluator.add(item, (timestamp, timestamp))
    assert all(f.status == "passed" for f in evaluator.finish())
    bad_clock = CorpusEvaluator(model, run_id)
    bad_clock.add(items[0], (epoch, epoch))
    bad_clock.add(items[1], (epoch - 1, epoch - 1))
    assert any(
        "capture_clock_nonmonotonic" in f.diagnostic and f.status == "unknown"
        for f in bad_clock.finish()
    )


def test_cli_apply_freezes_explicit_logs_and_does_not_ignore_missing_prerequisites(tmp_path):
    from protocol_lab.cli.main import main

    document = json.loads((FIXTURES / "a4-model.json").read_text())
    document["corpus_checks"].append(dict(kind="event_association", name="action", after_ns=10**9))
    model_path, log_path, mapping_path = (
        tmp_path / name for name in ("model.json", "actions.json", "mapping.json")
    )
    model_path.write_text(json.dumps(document))
    log_path.write_text('[{"time":1700000000,"action":"arbitrary action label"}]')
    mapping_path.write_text(
        json.dumps(dict(timestamp_field="time", label_field="action", timestamp_format="unix_s"))
    )
    arguments = [
        "apply",
        "--model",
        str(model_path),
        "--capture",
        str(FIXTURES / "crc-holdout.pcap"),
    ]
    missing, supplied = tmp_path / "missing.json", tmp_path / "supplied.json"
    assert main([*arguments, "--output", str(missing)]) == 0
    assert (
        main(
            [
                *arguments,
                "--output",
                str(supplied),
                "--action-log",
                str(log_path),
                "--log-mapping",
                str(mapping_path),
            ]
        )
        == 0
    )
    before = json.loads(missing.read_text())
    after = json.loads(supplied.read_text())
    assert all(
        row["status"] == "unknown" for row in before["results"] if row.get("check_name") == "action"
    )
    assert all(
        row["status"] == "passed" for row in after["results"] if row.get("check_name") == "action"
    )
    assert after["run"]["snapshot"]["action_logs"][0]["sha256"] == sha256_file(log_path)


def discovery_document(path):
    capture_id = uuid5(NAMESPACE_URL, f"protocol-lab:capture:{sha256_file(path)}")
    return json.dumps(
        dict(
            corpus_version_id=str(uuid4()),
            detectors=[dict(family="framing"), dict(family="checksums")],
            split=dict(
                discovery_ids=[str(capture_id)], holdout_unavailable_reason="Synthetic discovery"
            ),
            search=dict(
                fixed_size_max=64,
                adjustment_min=-8,
                adjustment_max=8,
                marker_max_bytes=4,
                max_marker_patterns=8,
            ),
            budget=dict(max_header_bytes=8, max_rule_trials=10000, max_checksum_operations=1000000),
        )
    )


def test_real_pcap_checksum_discovery_draft_holdout_and_counterexample():
    path = FIXTURES / "crc-discovery.pcap"
    output = io.StringIO()
    run = infer_files([path], discovery_document(path), output)
    assert run.rule_trials <= run.snapshot.spec.budget.max_rule_trials
    body = json.loads(output.getvalue())
    candidates = [
        InferenceCandidate.model_validate(c)
        for c in body["candidates"]
        if c["family"] == "checksums"
    ]
    expected = [
        c
        for c in candidates
        if c.rule.algorithm == "CRC-32/ISO-HDLC"
        and c.rule.field_relative_to == "message_end"
        and c.rule.field.endian == "little"
    ]
    assert expected and any(c.id == expected[0].id for c in candidates[:5])
    candidate = expected[0]
    draft = model_draft(candidate)
    assert draft.compilable
    model = load_model(draft.document_json)
    for fixture, failed in (("crc-holdout.pcapng", False), ("crc-counterexample.pcap", True)):
        applied = io.StringIO()
        counts = apply_capture(model, FIXTURES / fixture, applied)
        assert bool(counts.message_counts["failed"]) is failed
        assert counts.message_counts["passed"] >= 3
        evaluated = io.StringIO()
        result = infer_files(
            [FIXTURES / fixture], None, evaluated, candidate_document=candidate.model_dump_json()
        )
        assert bool(result.evaluation.metrics.contradicted) is failed
        assert result.evaluation.metrics.matched >= 3


def test_saved_a4_model_runs_local_and_corpus_checks_on_new_capture():
    model = load_model((FIXTURES / "a4-model.json").read_text())
    output = io.StringIO()
    counts = apply_capture(model, FIXTURES / "crc-holdout.pcap", output)
    assert counts.message_counts["passed"] == 4
    assert counts.corpus_check_counts["passed"] == 3
    assert counts.corpus_check_counts["unknown"] == 1
    body = json.loads(output.getvalue())
    assert any(item["kind"] == "corpus_check" for item in body["results"])
    assert len({item["id"] for item in body["results"]}) == len(body["results"])


def test_a4_report_reads_exact_candidate_evidence_from_derived_artifact(tmp_path, monkeypatch):
    from protocol_lab.reports import render

    path = FIXTURES / "crc-discovery.pcap"
    output = io.StringIO()
    infer_files([path], discovery_document(path), output)
    body = json.loads(output.getvalue())
    candidate = next(
        c
        for c in body["candidates"]
        if c["family"] == "checksums" and c["rule"]["algorithm"] == "CRC-32/ISO-HDLC"
    )
    fact = next(f for f in body["evidence"] if f["candidate_id"] == candidate["id"])
    assert fact["sources"]
    derived = tmp_path / "derived"
    derived.mkdir()
    line = (json.dumps({"kind": "evidence", "value": fact}) + "\n").encode()
    (derived / "inference.jsonl").write_bytes(line)
    records = [
        ("projects", {"id": body["result"]["snapshot"]["project_id"], "name": "A4 report"}),
        (
            "inference_runs",
            {
                "id": body["result"]["id"],
                "relative_path": "derived/inference.jsonl",
                "metadata_json": body["result"],
            },
        ),
        ("inference_candidates", {"metadata_json": candidate}),
        (
            "inference_evidence",
            {
                "candidate_id": candidate["id"],
                "run_id": candidate["run_id"],
                "evaluation_id": None,
                "status": fact["status"],
                "file_offset": 0,
                "length": len(line),
            },
        ),
    ]
    monkeypatch.setattr(render, "rows", lambda directory: iter(records))
    report = io.StringIO()
    render.render_report(tmp_path, report)
    assert "CRC-32/ISO-HDLC" in report.getvalue()
    assert fact["sources"][0]["packet_id"] in report.getvalue()
    assert "expected" in report.getvalue()
