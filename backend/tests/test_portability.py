import io
import json
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from protocol_lab.capture.index import WorkCancelled, sha256_file
from protocol_lab.cli.main import main
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.schema import ProtocolModel
from protocol_lab.services.application import apply_capture
from protocol_lab.storage.portable import (
    TABLES,
    Bundle,
    Member,
    member_path,
    pack,
    unpack,
    verify_bundle,
)
from protocol_lab.storage.projects import ProjectManifest, StorageError

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def minimal_bundle(tmp_path):
    directory = tmp_path / "bundle"
    directory.mkdir()
    from datetime import UTC, datetime

    manifest = ProjectManifest(project_id=uuid4(), created_at=datetime.now(UTC))
    (directory / "manifest.json").write_text(manifest.model_dump_json())
    (directory / "metadata.jsonl").write_text("")
    bundle = Bundle(
        project_id=manifest.project_id,
        members={
            name: Member(
                sha256=sha256_file(directory / name), size_bytes=(directory / name).stat().st_size
            )
            for name in ["manifest.json", "metadata.jsonl"]
        },
        table_counts={name: 0 for name in TABLES},
    )
    (directory / "bundle.json").write_text(bundle.model_dump_json())
    return directory, bundle


def test_legacy_0006_bundle_inventory_is_adapted_without_relabelling(tmp_path):
    directory, bundle = minimal_bundle(tmp_path)
    value = bundle.model_dump(mode="json")
    value["format_version"] = 1
    value["metadata_schema_revision"] = "0006_validation"
    value["table_counts"] = {
        name: count
        for name, count in value["table_counts"].items()
        if not name.startswith("inference_")
    }
    (directory / "bundle.json").write_text(json.dumps(value))
    restored = verify_bundle(directory)
    assert restored.format_version == 1 and restored.metadata_schema_revision == "0006_validation"
    value["table_counts"]["inference_runs"] = 0
    (directory / "bundle.json").write_text(json.dumps(value))
    with pytest.raises(StorageError, match="manifest invalid"):
        verify_bundle(directory)


@pytest.mark.parametrize(
    "name",
    [
        "../x",
        "/tmp/x",
        "sources/../x",
        "sources\\x",
        "C:/x",
        "./sources/x",
        "sources//x",
        "sources/",
        ".staging/x",
        "exports/x",
    ],
)
def test_archive_rejects_unsafe_paths_before_writing(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as file:
        file.writestr(name, "unsafe")
    with pytest.raises(StorageError):
        unpack(archive, tmp_path / "restore")
    assert not (tmp_path / "x").exists()


def test_archive_rejects_duplicate_link_and_oversized_members(tmp_path):
    archive = tmp_path / "bad.zip"
    info = zipfile.ZipInfo("sources/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as file:
        file.writestr(info, "../private")
    with pytest.raises(StorageError, match="links"):
        unpack(archive, tmp_path / "link")
    with zipfile.ZipFile(archive, "w") as file:
        file.writestr("manifest.json", "a")
        with pytest.warns(UserWarning):
            file.writestr("manifest.json", "b")
    with pytest.raises(StorageError, match="duplicate"):
        unpack(archive, tmp_path / "duplicate")


def test_bundle_checks_versions_hashes_extra_files_and_cancel(tmp_path):
    directory, bundle = minimal_bundle(tmp_path)
    archive = tmp_path / "project.zip"
    pack(directory, archive)
    assert unpack(archive, tmp_path / "new") == bundle
    assert main(["project", "verify", "--directory", str(directory)]) == 0
    with pytest.raises(WorkCancelled):
        verify_bundle(directory, lambda: True)
    (directory / "metadata.jsonl").write_text("changed")
    with pytest.raises(StorageError, match="checksum"):
        verify_bundle(directory)
    (directory / "metadata.jsonl").write_text("")
    value = bundle.model_dump(mode="json")
    value["format_version"] = 100
    (directory / "bundle.json").write_text(json.dumps(value))
    with pytest.raises(StorageError, match="manifest invalid"):
        verify_bundle(directory)
    (directory / "bundle.json").write_text(bundle.model_dump_json())
    (directory / "extra").write_text("unlisted")
    with pytest.raises(StorageError, match="unlisted"):
        verify_bundle(directory)


def test_cli_on_new_capture_expected_results_and_exact_provenance(tmp_path):
    output = tmp_path / "result.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "protocol_lab.cli",
            "apply",
            "--model",
            str(FIXTURES / "cli/length-model.json"),
            "--capture",
            str(FIXTURES / "framing/length-big.pcap"),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    actual = json.loads(output.read_text())
    messages = [r for r in actual["results"] if r["kind"] == "message"]
    assert [r["status"] for r in messages] == ["passed", "failed", "failed"]
    assert [r["fields"][0]["value"] for r in messages] == ["3", "5", "1"]
    assert actual["run"]["coverage"]["stream_bytes"] == 15
    assert actual["run"]["coverage"]["message_counts"] == {
        "passed": 1,
        "failed": 2,
        "unknown": 0,
        "ambiguous": 0,
        "not_applicable": 0,
    }
    spans = actual["provenance"]["sessions"][0]["streams"][0]["spans"]
    assert len(spans[0]["sources"]) == 1
    assert spans[0]["sources"][0]["packet_index"] == 3
    assert spans[0]["sources"][0]["packet_payload_range"] == {"start": 0, "end": 1}
    assert (
        main(
            [
                "apply",
                "--model",
                str(FIXTURES / "cli/length-model.json"),
                "--capture",
                str(FIXTURES / "framing/length-big.pcap"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert json.loads(output.read_text()) == actual
    expected = json.loads((FIXTURES / "cli/expected.json").read_text())
    for name, reference in expected.items():
        destination = io.StringIO()
        model = ProtocolModel.model_validate_json((FIXTURES / "cli/length-model.json").read_text())
        coverage = apply_capture(model, FIXTURES / name, destination)
        assert coverage.message_counts == reference["message_counts"]
        assert coverage.stream_bytes == reference["stream_bytes"]


@pytest.mark.parametrize(
    "capture",
    [
        "tcp/gaps-overlaps.pcap",
        "unsupported-link.pcap",
        "mixed-diagnostics.pcap",
        "multi-interface.pcapng",
    ],
)
def test_cli_partial_unknown_ambiguous_and_unsupported_are_explicit(capture):
    model = ProtocolModel.model_validate(
        dict(
            schema_version="interpretation-1",
            name="Raw",
            framing={"rule": {"kind": "fixed", "size": 5}},
            fields=[dict(kind="bytes", name="raw", length="remaining")],
        )
    )
    destination = io.StringIO()
    counts = apply_capture(model, FIXTURES / capture, destination)
    actual = json.loads(destination.getvalue())
    assert sum(counts.byte_counts.values()) == counts.stream_bytes
    if capture == "tcp/gaps-overlaps.pcap":
        assert counts.counts["ambiguous"] > 0 and counts.counts["unknown"] > 0
        assert counts.unavailable_source_bytes > 0
    if capture == "unsupported-link.pcap":
        assert actual["results"][0]["status"] == "unknown"
        assert counts.noneligible_packets == 1


def test_cli_invalid_model_or_capture_never_publishes_partial_output(tmp_path):
    broken = tmp_path / "broken"
    broken.write_text("{}")
    output = tmp_path / "output.json"
    assert (
        main(
            [
                "apply",
                "--model",
                str(broken),
                "--capture",
                str(FIXTURES / "ordered.pcap"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()
    assert (
        main(
            [
                "apply",
                "--model",
                str(FIXTURES / "cli/length-model.json"),
                "--capture",
                str(broken),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()
    assert not list(tmp_path.glob(".protocol-lab-*"))
    with pytest.raises(StorageError):
        member_path("../private")


def test_zip_expanded_limit_and_bundle_symlinks(tmp_path, monkeypatch):
    from protocol_lab.storage import portable

    archive = tmp_path / "oversize.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as file:
        file.writestr("sources/large", b"x" * 2048)
    monkeypatch.setattr(portable, "MAX_MEMBER_BYTES", 1024)
    with pytest.raises(StorageError, match="exceeds"):
        unpack(archive, tmp_path / "expanded")
    directory, _ = minimal_bundle(tmp_path)
    metadata = directory / "metadata.jsonl"
    metadata.unlink()
    original = tmp_path / "original"
    original.write_text("")
    metadata.symlink_to(original)
    with pytest.raises(StorageError, match="symlink"):
        verify_bundle(directory)


@pytest.mark.parametrize("capture", ["isolated-ambiguous.pcap", "conflicting-server-syn.pcap"])
def test_cli_keeps_failed_reconstruction_directions_in_coverage(capture):
    model = ProtocolModel.model_validate(
        dict(
            schema_version="interpretation-1",
            name="Raw",
            framing={"rule": {"kind": "fixed", "size": 4}},
            fields=[dict(kind="bytes", name="raw", length="remaining")],
        )
    )
    output = io.StringIO()
    coverage = apply_capture(model, FIXTURES / "tcp" / capture, output)
    actual = json.loads(output.getvalue())
    (failure,) = actual["run"]["snapshot"]["sources"][0]["reconstruction_failures"]
    (item,) = [r for r in actual["results"] if r["kind"] == "reconstruction_diagnostic"]
    assert item["status"] == "unknown" and item["session_id"] == failure["session_id"]
    assert item["direction"] == failure["direction"]
    assert failure["diagnostic"] in item["diagnostic"]
    assert item["anchor"] is None and item["stream_id"] is None
    assert coverage.unreconstructed_directions == 1
    assert coverage.counts["unknown"] >= 1
    assert coverage.message_counts["passed"] >= 1
    assert sum(coverage.byte_counts.values()) == coverage.stream_bytes


@pytest.mark.parametrize(
    "properties,reason",
    [
        ('"constant": 65, "constant": 66', "Duplicate JSON property"),
        ('"constant": NaN', "Invalid JSON constant"),
        ('"constant": Infinity', "Invalid JSON constant"),
    ],
)
def test_cli_and_gui_reject_same_ambiguous_model_documents(tmp_path, capsys, properties, reason):
    from fastapi.testclient import TestClient

    from protocol_lab.api.app import create_app
    from protocol_lab.services.settings import Settings

    document = json.dumps(
        dict(
            schema_version="interpretation-1",
            name="Checks",
            framing={"rule": {"kind": "fixed", "size": 1}},
            fields=[dict(kind="int", name="x", width=1, signed=False, endian="big", constant=65)],
        )
    ).replace('"constant": 65', properties)
    with pytest.raises(ValueError, match=reason):
        load_model(document)
    with TestClient(create_app(Settings())) as client:
        assert (
            client.post(
                "/api/v1/interpretations/check",
                json={"document_json": document},
            ).json()["valid"]
            is False
        )
    path, output = tmp_path / "model.json", tmp_path / "output.json"
    path.write_text(document)
    assert (
        main(
            [
                "apply",
                "--model",
                str(path),
                "--capture",
                str(FIXTURES / "ordered.pcap"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert reason in capsys.readouterr().err
    assert not output.exists() and not list(tmp_path.glob(".protocol-lab-*"))


def test_cli_technical_limit_is_unknown_and_preserves_original_provenance(tmp_path):
    from protocol_lab.interpretation.schema import ProtocolModel

    model = dict(
        schema_version="interpretation-1",
        name="Array budget",
        max_array_items=2,
        framing=dict(rule=dict(kind="length", width=2, adjustment=2)),
        fields=[
            dict(kind="int", name="n", width=2, signed=False, endian="big"),
            dict(
                kind="array",
                name="items",
                count={"field": "n"},
                fields=[dict(kind="int", name="v", width=1, signed=False, endian="big")],
            ),
        ],
    )
    source = FIXTURES / "interpretation/arrays-new-parameters.pcap"
    before = source.read_bytes()
    results = []
    for limit in (2, 4):
        model["max_array_items"] = limit
        output = io.StringIO()
        apply_capture(ProtocolModel.model_validate(model), source, output)
        results.append(json.loads(output.getvalue()))
    first, second = results
    item = next(row for row in first["results"] if row["kind"] == "message")
    assert item["status"] == "unknown"
    assert item["technical_limit"]["observed"] == "4"
    assert item["technical_limit"]["maximum"] == "2"
    assert second["run"]["coverage"]["message_counts"]["passed"] == 1
    assert first["provenance"] == second["provenance"] and source.read_bytes() == before


def test_historical_validation_json_without_new_fields_remains_exportable(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from protocol_lab.services import portability
    from protocol_lab.validation.models import ValidationRun

    output = io.StringIO()
    apply_capture(
        load_model((FIXTURES / "cli/length-model.json").read_text()),
        FIXTURES / "framing/length-big.pcap",
        output,
    )
    legacy = json.loads(output.getvalue())
    legacy["run"]["snapshot"]["engine_version"] = "validation-v1"
    for source in legacy["run"]["snapshot"]["sources"]:
        source.pop("reconstruction_failures")
    for key in ["unreconstructed_directions", "excluded_unreconstructed_directions"]:
        legacy["run"]["coverage"].pop(key)
    for item in legacy["results"]:
        item.pop("direction")
        item.pop("technical_limit")
    artifact = tmp_path / "legacy.jsonl"
    artifact.write_text(
        json.dumps(legacy["run"])
        + "\n"
        + "".join(json.dumps(item) + "\n" for item in legacy["results"])
    )
    run = ValidationRun.model_validate(legacy["run"])

    class Database:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def get(self, *_):
            return SimpleNamespace(relative_path="legacy.jsonl", sha256=sha256_file(artifact))

    monkeypatch.setattr(portability, "Session", lambda _: Database())
    monkeypatch.setattr(
        portability, "ValidationStore", lambda _: SimpleNamespace(get=lambda _: run)
    )
    projects = SimpleNamespace(engine=None, safe_path=lambda *_: artifact)
    destination = io.StringIO()
    portability.validation_json(projects, run.snapshot.id, destination)
    exported = json.loads(destination.getvalue())
    assert exported["run"] == legacy["run"]
    assert exported["results"] == legacy["results"]
    assert run.coverage.unreconstructed_directions == 0
