"""Real PostgreSQL A4 workflow, restored into another isolated DB schema and root."""

import io
import json
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from test_storage_integration import destination_store, finish, upload
from test_storage_integration import storage as storage

from protocol_lab.api.app import create_app
from protocol_lab.interpretation.document import load_model
from protocol_lab.reports.render import render_report
from protocol_lab.services.application import apply_capture
from protocol_lab.storage.portable import restore, snapshot, verify_bundle

FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/inference"


def test_a4_crc_draft_relations_gui_cli_report_and_relocated_restore(
    storage, tmp_path, monkeypatch
):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "A4 acceptance"}).json()["id"]
        captures = []
        for name in ("crc-discovery", "crc-holdout"):
            imported = finish(client, upload(client, project, f"inference/{name}.pcap"))
            assert imported["status"] == "succeeded", imported
            capture = imported["result"]["capture_id"]
            rebuilt = finish(
                client, client.post(f"/api/v1/captures/{capture}/reconstruct", json={}).json()["id"]
            )
            assert rebuilt["status"] == "succeeded", rebuilt
            captures.append(capture)
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={
                "name": "CRC captures",
                "spec": {"capture_ids": captures},
            },
        ).json()
        spec = dict(
            corpus_version_id=corpus["id"],
            detectors=[dict(family="framing"), dict(family="checksums")],
            split=dict(discovery_ids=captures[:1], holdout_ids=captures[1:]),
            search=dict(
                fixed_size_max=64,
                adjustment_min=-8,
                adjustment_max=8,
                marker_max_bytes=4,
                max_marker_patterns=8,
            ),
            budget=dict(max_header_bytes=8, max_rule_trials=10000),
        )
        searched = finish(
            client,
            client.post(
                f"/api/v1/projects/{project}/inference-runs",
                json={
                    "document_json": json.dumps(spec),
                },
            ).json()["id"],
        )
        assert searched["status"] == "succeeded", searched
        run_id = searched["result"]["run_id"]
        page = client.get(f"/api/v1/inference-runs/{run_id}/candidates?family=checksums").json()
        candidates = [
            client.get(f"/api/v1/inference-candidates/{item['id']}").json()
            for item in page["items"]
        ]
        candidate = next(
            item
            for item in candidates
            if item["rule"]["algorithm"] == "CRC-32/ISO-HDLC"
            and item["rule"]["field_relative_to"] == "message_end"
            and item["rule"]["field"]["endian"] == "little"
        )
        checked = finish(
            client,
            client.post(
                f"/api/v1/inference-candidates/{candidate['id']}/evaluations",
                json={"holdout": True},
            ).json()["id"],
        )
        assert checked["status"] == "succeeded", checked
        draft = client.post(
            f"/api/v1/inference-candidates/{candidate['id']}/model-draft", json={}
        ).json()
        assert draft["compilable"] and "checksum" in draft["document_json"]
        saved = client.post(
            f"/api/v1/projects/{project}/interpretations",
            json={
                "document_json": (FIXTURES / "a4-model.json").read_text(),
                "parent_id": None,
            },
        ).json()
        validated = finish(
            client,
            client.post(
                f"/api/v1/projects/{project}/validation-runs",
                json={
                    "corpus_version_id": corpus["id"],
                    "interpretation_version_id": saved["id"],
                },
            ).json()["id"],
        )
        assert validated["status"] == "succeeded", validated
        validation_id = validated["result"]["run_id"]
        before = client.get(f"/api/v1/validation-runs/{validation_id}").json()
        assert before["coverage"]["corpus_check_counts"]["passed"] >= 7
        summaries = client.get(f"/api/v1/validation-runs/{validation_id}/results?limit=100").json()[
            "items"
        ]
        gui = [
            client.get(f"/api/v1/validation-runs/{validation_id}/results/{item['id']}").json()
            for item in summaries
            if item["capture_id"] == captures[1]
        ]
        output = io.StringIO()
        apply_capture(
            load_model(saved["document_json"]),
            FIXTURES / "crc-holdout.pcap",
            output,
            capture_id=UUID(captures[1]),
        )
        cli = json.loads(output.getvalue())["results"]

        def signature(rows):
            return sorted(
                (
                    row["kind"],
                    row["status"],
                    row["diagnostic"],
                    json.dumps(row["fields"], sort_keys=True),
                )
                for row in rows
            )

        assert signature(gui) == signature(cli)
        bundle_path = tmp_path / "a4-bundle"
        snapshot(repository, UUID(project), bundle_path)
        assert verify_bundle(bundle_path).metadata_schema_revision == "0007_inference"
        report = io.StringIO()
        render_report(bundle_path, report)
        assert "CRC-32/ISO-HDLC" in report.getvalue()
        assert "checksum_relation" in report.getvalue()
    with destination_store(storage, tmp_path, monkeypatch) as (destination, destination_settings):
        restore(destination, bundle_path)
        with TestClient(create_app(destination_settings)) as client:
            assert client.get(f"/api/v1/validation-runs/{validation_id}").json() == before
            evidence = client.get(f"/api/v1/inference-candidates/{candidate['id']}/evidence").json()
            assert evidence["items"][0]["sources"]
            result = evidence["items"][0]["anchor"]
            interval = result["byte_range"]
            assert (
                client.get(
                    f"/api/v1/streams/{result['stream_id']}/bytes?offset={interval['start']}"
                    f"&length={interval['end'] - interval['start']}"
                ).status_code
                == 200
            )
