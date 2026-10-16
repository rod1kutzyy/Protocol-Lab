"""Strict inference documents and stable discovery/holdout boundaries."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter, ValidationError

from protocol_lab.api.app import create_app
from protocol_lab.domain.models import StreamRange
from protocol_lab.inference.document import load_document
from protocol_lab.inference.models import (
    SCHEMAS,
    CandidateRule,
    DataSplit,
    InferenceCandidate,
    InferenceCoverage,
    InferenceMetrics,
    InferenceSnapshot,
    InferenceSpec,
    SearchBudget,
    SearchSpace,
    TransformMapping,
    content_hash,
    json_schema,
)
from protocol_lab.inference.sampling import SampleUnit, select_sample, validate_split
from protocol_lab.services.settings import Settings
from protocol_lab.validation.models import CaptureSnapshot

FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/inference"
CAPTURE, HOLDOUT, CORPUS, PROJECT = (UUID(int=n) for n in (16, 32, 1, 2))


def spec(**updates):
    document = json.loads((FIXTURES / "spec.json").read_text())
    document.update(updates)
    return InferenceSpec.model_validate(document)


def source(capture=CAPTURE, sessions=2):
    return CaptureSnapshot(
        id=capture,
        sha256=hashlib.sha256(str(capture).encode()).hexdigest(),
        size_bytes=100,
        packet_count=10,
        eligible_packets=10,
        checksum_policy="warn",
        import_settings={},
        import_engine_version="capture-v1",
        diagnostics={},
        reconstruction_id=UUID(int=capture.int + 1000),
        reconstruction_sha256="1" * 64,
        reconstruction_settings={},
        reconstruction_engine_version="tcp-v1",
        streams=tuple(
            dict(
                id=UUID(int=capture.int * 100 + i),
                session_id=UUID(int=capture.int * 10 + i),
                reconstruction_version="tcp-v1",
                reconstruction_policy="retain-all-overlaps",
                extent=1000,
                direction="a_to_b",
                included=True,
            )
            for i in range(sessions)
        ),
    )


def unit(capture, stream_index, offset, payload, status="known"):
    stream = capture.streams[stream_index]
    return SampleUnit(
        capture_id=capture.id,
        session_id=stream.session_id,
        anchor=StreamRange(
            stream_id=stream.id,
            reconstruction_version="tcp-v1",
            byte_range=dict(start=offset, end=offset + len(payload)),
        ),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        data_status=status,
    )


def snapshot_document():
    return dict(
        project_id=str(PROJECT),
        spec=json.loads(spec().model_dump_json()),
        corpus=dict(
            id=str(CORPUS),
            corpus_id=str(UUID(int=3)),
            project_id=str(PROJECT),
            name="inference contracts",
            spec=dict(capture_ids=[str(CAPTURE), str(HOLDOUT)]),
            sha256="0" * 64,
            created_at=datetime.now(UTC).isoformat(),
        ),
        sources=[json.loads(s.model_dump_json()) for s in (source(), source(HOLDOUT))],
        engines=dict(
            inference="not-implemented",
            framing="framing-v2",
            interpretation="interpretation-v2",
            validation="validation-v3",
            ranking="lexicographic-1",
        ),
    )


def test_spec_round_trip_defaults_and_schema_artifacts():
    actual = load_document((FIXTURES / "spec.json").read_text())
    assert actual == spec()
    assert actual.budget.max_sample_messages == 5000
    assert actual.search.fixed_size_max == 4096
    assert actual == load_document(actual.model_dump_json())
    for name in SCHEMAS:
        schema = json_schema(name)
        assert schema["$schema"].endswith("2020-12/schema")
        exported = FIXTURES.parents[2] / "docs/schemas/inference" / f"{name}.schema.json"
        assert json.loads(exported.read_text()) == schema


def test_exported_openapi_matches_runtime(tmp_path):
    exported = FIXTURES.parents[2] / "docs/openapi.json"
    app = create_app(Settings(database_url=None, project_root=tmp_path))
    assert json.loads(exported.read_text(encoding="utf-8")) == app.openapi()


@pytest.mark.parametrize(
    "change",
    [
        {"mode": "evaluate"},
        {"candidate_ids": [str(UUID(int=4))]},
        {"detectors": [{"family": "framing"}, {"family": "framing"}]},
        {"detectors": [{"family": "eval"}]},
        {"python": "print('unsafe')"},
        {"budget": {"max_sample_messages": True}},
        {"budget": {"max_scanned_bytes": 0}},
        {"search": {"fixed_size_min": 10, "fixed_size_max": 1}},
        {"search": {"widths": [True]}},
        {"search": {"endians": ["big", "big"]}},
        {"schema_version": "inference-spec-9"},
    ],
)
def test_invalid_and_executable_specs_rejected(change):
    with pytest.raises(ValidationError):
        spec(**change)


@pytest.mark.parametrize(
    "document",
    [
        '{"mode":"discover","mode":"evaluate"}',
        '{"budget":{"x":1,"x":2}}',
        '{"seed":NaN}',
        '{"seed":Infinity}',
        '{"seed":-Infinity}',
        "[" * 2000 + "0" + "]" * 2000,
        " " * (512 * 1024 + 1),
    ],
)
def test_ambiguous_json_and_document_limits(document):
    with pytest.raises(ValueError):
        load_document(document)


def test_overflowing_json_exponent_cannot_hide_in_nested_metadata():
    with pytest.raises(ValueError, match="Non-finite JSON number"):
        load_document('{"source":{"import_settings":{"number":1e400}}}', "snapshot")


def test_split_requires_explicit_holdout_or_reason_and_no_overlap():
    with pytest.raises(ValidationError, match="disjoint"):
        DataSplit(discovery_ids=[CAPTURE], holdout_ids=[CAPTURE])
    with pytest.raises(ValidationError, match="reason"):
        DataSplit(discovery_ids=[CAPTURE])
    with pytest.raises(ValidationError, match="Duplicate"):
        DataSplit(discovery_ids=[CAPTURE, CAPTURE], holdout_ids=[HOLDOUT])
    split = DataSplit(discovery_ids=[CAPTURE], holdout_unavailable_reason="Only one recording")
    assert split.holdout_ids == ()


def test_snapshot_checks_scope_versions_and_same_recording_leakage():
    document = snapshot_document()
    snapshot = load_document(json.dumps(document), "snapshot")
    assert isinstance(snapshot, InferenceSnapshot)
    document["project_id"] = str(UUID(int=99))
    with pytest.raises(ValidationError, match="project mismatch"):
        load_document(json.dumps(document), "snapshot")
    document = snapshot_document()
    document["sources"].pop()
    with pytest.raises(ValidationError, match="every selected capture"):
        load_document(json.dumps(document), "snapshot")
    a, b = source(), source(HOLDOUT)
    with pytest.raises(ValueError, match="Duplicate capture bytes"):
        validate_split(spec(), (a, b.model_copy(update={"sha256": a.sha256})))
    configured = spec(recording_groups=[dict(capture_ids=[CAPTURE, HOLDOUT], rationale="Two taps")])
    with pytest.raises(ValueError, match="recording group"):
        validate_split(configured, (a, b))


def test_sample_is_order_independent_stratified_and_preserves_duplicate_sources():
    a, b = source(), source(HOLDOUT)
    units = [unit(a, i % 2, i * 4, bytes([i, 1, 2, 3])) for i in range(10)]
    units += [
        unit(a, 0, 100, bytes([0, 1, 2, 3])),
        unit(b, 0, 0, b"TEST"),
        unit(a, 0, 104, b"????", "ambiguous"),
    ]
    configured = spec(budget={"max_sample_messages": 4})
    selected = select_sample(configured, (a, b), units)
    assert selected == select_sample(configured, (b, a), reversed(units))
    assert len(selected.entries) == 4 and selected.unselected_unique_units == 6
    assert selected.duplicate_units == 1 and selected.holdout_units == 1
    assert selected.discovery_units == 12 and selected.uncertain_units == 1
    assert len({e.representative.session_id for e in selected.entries}) == 2
    assert all(o.capture_id == CAPTURE for e in selected.entries for o in e.occurrences)
    complete = select_sample(spec(), (a, b), units)
    assert sum(len(e.occurrences) for e in complete.entries) == 11


def test_sample_budgets_source_ranges_and_retransmissions_are_explicit():
    sources = (source(), source(HOLDOUT))
    item = unit(sources[0], 0, 0, b"ABC")
    with pytest.raises(ValueError, match="max_sample_units"):
        select_sample(spec(budget={"max_sample_units": 1}), sources, [item, item])
    with pytest.raises(ValueError, match="retransmissions"):
        select_sample(spec(), sources, [item, item])
    wrong = item.model_copy(update={"capture_id": HOLDOUT})
    with pytest.raises(ValueError, match="frozen included stream"):
        select_sample(spec(), sources, [wrong])


def test_sample_exclusions_cancellation_and_holdout_anchors_are_not_hidden():
    from protocol_lab.capture.index import WorkCancelled

    a, b = source(), source(HOLDOUT)
    item = unit(a, 0, 0, b"ABC")
    excluded = {**item.anchor.model_dump(mode="json"), "byte_range": dict(start=1, end=2)}
    configured = spec(excluded_ranges=[excluded])
    selected = select_sample(configured, (a, b), [item])
    assert selected.entries == () and selected.excluded_units == 1
    assert selected.discovery_units == 1
    with pytest.raises(WorkCancelled):
        select_sample(spec(), (a, b), [item], cancelled=lambda: True)
    document = snapshot_document()
    document["sample_anchors"] = [unit(b, 0, 0, b"ABC").anchor.model_dump(mode="json")]
    with pytest.raises(ValidationError, match="only included discovery"):
        load_document(json.dumps(document), "snapshot")


def test_candidate_hash_family_ranking_and_unsupported_compilation_are_checked():
    rule = TypeAdapter(CandidateRule).validate_json(
        '{"kind":"byte_profile","measurement":"within_block"}'
    )
    document = dict(
        id=str(UUID(int=100)),
        run_id=str(UUID(int=101)),
        family="entropy",
        detector_version="test-1",
        rule=json.loads(rule.model_dump_json()),
        rule_sha256=content_hash(rule),
        scope=dict(corpus_version_id=str(CORPUS), capture_ids=[str(CAPTURE)]),
        metrics=dict(
            unit="message",
            eligible=1,
            matched=1,
            contradicted=0,
            unknown=0,
            ambiguous=0,
            not_applicable=0,
            captures=1,
            sessions=1,
            unique_messages=1,
        ),
        ranking=dict(
            supporting_sessions=1,
            matched=1,
            checked=1,
            explained_bytes=4,
            contradictions=0,
            free_parameters=1,
        ),
        rationale="Descriptive statistics only",
        compiler_support="not_compilable",
        compiler_reason="A profile does not establish field semantics",
    )
    candidate = InferenceCandidate.model_validate(document)
    assert load_document(candidate.model_dump_json(), "candidate") == candidate
    for change in [
        dict(rule_sha256="0" * 64),
        dict(family="checksums"),
        dict(compiler_support="interpretation-1"),
        dict(compiler_reason=None),
    ]:
        with pytest.raises(ValidationError):
            InferenceCandidate.model_validate({**document, **change})


def test_evaluation_snapshot_requires_exact_fixed_candidate_rule():
    rule = TypeAdapter(CandidateRule).validate_json(
        '{"kind":"byte_profile","measurement":"within_block"}'
    )
    document = snapshot_document()
    document["spec"]["mode"] = "evaluate"
    document["spec"]["candidate_ids"] = [str(UUID(int=100))]
    with pytest.raises(ValidationError, match="not frozen"):
        load_document(json.dumps(document), "snapshot")
    document["candidates"] = [
        dict(
            id=str(UUID(int=100)),
            sha256=content_hash(rule),
            rule=json.loads(rule.model_dump_json()),
        )
    ]
    assert load_document(json.dumps(document), "snapshot").candidates[0].id == UUID(int=100)
    document["candidates"][0]["sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="rule hash mismatch"):
        load_document(json.dumps(document), "snapshot")


def test_session_split_keeps_entire_connection_together():
    a = source()
    ids = [s.session_id for s in a.streams]
    configured = spec(split=dict(unit="session", discovery_ids=[ids[0]], holdout_ids=[ids[1]]))
    selected = select_sample(configured, (a,), [unit(a, 0, 0, b"AB"), unit(a, 1, 0, b"CD")])
    assert selected.holdout_units == 1 and len(selected.entries) == 1
    with pytest.raises(ValueError, match="every selected"):
        validate_split(configured, (a, source(HOLDOUT)))


def test_closed_rule_union_and_checksum_parameters_are_not_executable():
    adapter = TypeAdapter(CandidateRule)
    rule = adapter.validate_json(
        json.dumps(
            dict(
                kind="length_framing", framing=dict(rule=dict(kind="length", width=2, adjustment=2))
            )
        )
    )
    assert rule.framing.rule.width == 2
    for invalid in [
        dict(kind="fixed_framing", framing=dict(rule=dict(kind="length"))),
        dict(kind="constant_region", offset=0, length=2),
        dict(kind="constant_region", offset=0, length=2, value_hex="aa"),
        dict(kind="counter", field=dict(offset=0, width=True, endian="big")),
        dict(kind="checksum_relation", algorithm="lambda b: 0", field={}, covered_ranges=[]),
        dict(kind="parameter_mapping", parameter_path=["text"], encoding="utf-8", bom=True),
    ]:
        with pytest.raises(ValidationError):
            adapter.validate_json(json.dumps(invalid))


def test_metrics_and_coverage_do_not_hide_unknown_units():
    metrics = dict(
        unit="message",
        eligible=4,
        matched=1,
        contradicted=1,
        unknown=1,
        ambiguous=1,
        not_applicable=2,
        captures=1,
        sessions=1,
        unique_messages=4,
    )
    assert InferenceMetrics(**metrics).eligible == 4
    with pytest.raises(ValidationError, match="account"):
        InferenceMetrics(**{**metrics, "eligible": 2})
    with pytest.raises(ValidationError, match="entire selected"):
        InferenceCoverage(
            stream_bytes=100,
            selected_bytes=80,
            excluded_bytes=20,
            known_bytes=80,
            unavailable_bytes=1,
            ambiguous_bytes=0,
            unframed_bytes=0,
        )


def test_base64_provenance_supports_different_lengths_without_fake_source_range():
    anchor = unit(source(), 0, 0, b"QUJD").anchor
    result = TransformMapping(
        anchor=anchor,
        transform="base64_standard",
        decoded_length=3,
        parts=[dict(source=dict(start=0, end=4), decoded=dict(start=0, end=3))],
    )
    assert result.parts[0].source.end == 4 and result.parts[0].decoded.end == 3
    with pytest.raises(ValidationError, match="coverage"):
        TransformMapping(**{**result.model_dump(), "decoded_length": 4})


def test_schema_and_spec_api_work_without_db_and_advertise_detector_capabilities(tmp_path):
    with TestClient(create_app(Settings(database_url=None, project_root=tmp_path))) as client:
        capability = client.get("/api/v1/inference/capabilities").json()
        assert capability["analysis_available"] is True
        assert {item["family"] for item in capability["detectors"] if item["available"]} == {
            "framing",
            "structure",
            "entropy",
            "groups",
            "events",
            "data_mapping",
            "counters",
            "tokens",
            "timestamps",
            "checksums",
        }
        for name in SCHEMAS:
            response = client.get(f"/api/v1/inference/schemas/{name}")
            assert response.status_code == 200 and response.json() == json_schema(name)
        checked = client.post(
            "/api/v1/inference/spec/check",
            json={"document_json": (FIXTURES / "spec.json").read_text()},
        ).json()
        assert checked["valid"] and not checked["scope_verified"]
        assert client.get("/api/v1/inference/schemas/python").status_code == 422
        assert (
            client.post(
                "/api/v1/inference/spec/check",
                json={"document_json": '{"mode":"discover","mode":"evaluate"}'},
            ).json()["valid"]
            is False
        )
        assert (
            client.post(
                "/api/v1/projects/00000000-0000-0000-0000-000000000001/inference-runs",
                json={"document_json": (FIXTURES / "spec.json").read_text()},
            ).status_code
            == 503
        )


def test_canonical_rule_hash_is_independent_of_json_key_order():
    first = TypeAdapter(CandidateRule).validate_json(
        '{"kind":"byte_profile","measurement":"within_block","window_bytes":32}'
    )
    second = TypeAdapter(CandidateRule).validate_json(
        '{"window_bytes":32,"measurement":"within_block","kind":"byte_profile"}'
    )
    assert content_hash(first) == content_hash(second)
    assert SearchBudget().max_sample_messages == 5000 and SearchSpace().marker_max_bytes == 16
