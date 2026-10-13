"""Real PostgreSQL tests, each in a newly generated isolated schema."""

import hashlib
import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from protocol_lab.api.app import create_app
from protocol_lab.capture.index import IndexSettings, index_capture
from protocol_lab.services.settings import Settings
from protocol_lab.storage.projects import ProjectStore, StorageError

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


@pytest.fixture
def storage(tmp_path, monkeypatch):
    database_url = os.getenv("PROTOCOL_LAB_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("Set PROTOCOL_LAB_TEST_DATABASE_URL for real PostgreSQL integration tests")
    schema = "pl_test_" + uuid4().hex
    admin = create_engine(database_url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = (
        make_url(database_url)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    monkeypatch.setenv("PROTOCOL_LAB_DATABASE_URL", url)
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    engine = create_engine(url)
    root = tmp_path / "projects"
    repository = ProjectStore(engine, root)
    yield repository, Settings(database_url=url, project_root=root), config
    engine.dispose()
    with admin.begin() as connection:
        connection.execute(
            text(f'DROP SCHEMA "{schema}" CASCADE')
        )  # Only this test-created schema.
    admin.dispose()


def finish(client, job_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = client.get(f"/api/v1/jobs/{job_id}")
        assert response.status_code == 200
        data = response.json()
        if data["status"] in {"succeeded", "failed", "cancelled"}:
            return data
        time.sleep(0.02)
    raise AssertionError("Import job did not finish")


def upload(client, project_id, name="ordered.pcap", policy="warn"):
    response = client.post(
        f"/api/v1/projects/{project_id}/captures",
        files={"file": ("untrusted/../../name", (FIXTURES / name).read_bytes())},
        data={"checksum_policy": policy},
    )
    assert response.status_code == 202, response.text
    return response.json()["id"]


def test_import_persistence_duplicates_provenance_and_immutability(storage):
    repository, settings, config = storage
    original = (FIXTURES / "ordered.pcap").read_bytes()
    checksum = hashlib.sha256(original).hexdigest()
    with TestClient(create_app(settings)) as client:
        project_response = client.post("/api/v1/projects", json={"name": "Research"})
        assert project_response.status_code == 201
        project_id = project_response.json()["id"]
        manifest = json.loads((settings.project_root / project_id / "manifest.json").read_text())
        assert manifest["format_version"] == 1
        assert "database_url" not in manifest
        job = finish(client, upload(client, project_id))
        assert job["status"] == "succeeded", job
        assert job["result"]["outcome"] == "imported"
        capture_id = job["result"]["capture_id"]
        capture = client.get(f"/api/v1/captures/{capture_id}").json()
        assert capture["sha256"] == checksum
        assert capture["import_settings"]["checksum_policy"] == "warn"
        assert capture["packet_count"] == 2
        stored = settings.project_root / project_id / capture["relative_path"]
        assert not Path(capture["relative_path"]).is_absolute()
        assert stored.read_bytes() == original
        assert (FIXTURES / "ordered.pcap").read_bytes() == original
        packets = client.get(f"/api/v1/captures/{capture_id}/packets?limit=1").json()
        assert packets["next_offset"] == 1
        packet = packets["items"][0]
        start = packet["file_offset"] + packet["payload_offset"]
        assert stored.read_bytes()[start : start + packet["payload_length"]] == b"HELLO"
        duplicate = finish(client, upload(client, project_id, policy="ignore"))
        assert duplicate["result"]["outcome"] == "already_imported"
        assert duplicate["result"]["capture_id"] == capture_id
        assert duplicate["result"]["checksum_policy"] == "warn"
        assert duplicate["result"]["requested_checksum_policy"] == "ignore"
        assert len(client.get(f"/api/v1/projects/{project_id}/captures").json()["items"]) == 1
        assert client.post(f"/api/v1/captures/{capture_id}/verify").json()["status"] == "verified"
    # Same metadata and files available after API restart; migrations are idempotent.
    command.upgrade(config, "head")
    command.check(config)
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/projects/{project_id}").status_code == 200
        assert (
            client.get(f"/api/v1/captures/{capture_id}/packets").json()["items"][0]["id"]
            == packet["id"]
        )
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def test_pcapng_and_bad_packet_alongside_good_are_indexed(storage):
    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Mixed"}).json()["id"]
        ng = finish(client, upload(client, project_id, "multi-interface.pcapng"))
        assert ng["status"] == "succeeded", ng
        assert ng["result"]["packet_count"] == 3
        mixed = finish(client, upload(client, project_id, "mixed-diagnostics.pcap"))
        assert mixed["status"] == "succeeded", mixed
        capture = client.get(f"/api/v1/captures/{mixed['result']['capture_id']}").json()
        assert capture["diagnostics"]["tcp_checksum_invalid"] == 1
        assert capture["diagnostics"]["capture_truncated"] == 1
        assert capture["packet_count"] == 4


def test_failed_cancelled_and_oversized_import_publish_no_capture(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Failure"}).json()["id"]
        client.app.state.jobs.max_workers = 0
        job_id = upload(client, project_id)
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelled"
        assert repository.captures(UUID(project_id), 0, 100) == []
        assert not list((settings.project_root / project_id / ".staging").iterdir())
        client.app.state.jobs.max_workers = 2
        data = (FIXTURES / "ordered.pcap").read_bytes()[:-1]
        response = client.post(
            f"/api/v1/projects/{project_id}/captures", files={"file": ("truncated.pcap", data)}
        )
        failure = finish(client, response.json()["id"])
        assert failure["status"] == "failed"
        assert failure["result"] is None
        assert "Truncated" in failure["error"]
        assert client.get("/api/v1/health").status_code == 200
        assert repository.captures(UUID(project_id), 0, 100) == []
        response = client.post(
            f"/api/v1/projects/{project_id}/captures", files={"file": ("bad", b"BAD!")}
        )
        assert response.status_code == 422
    from dataclasses import replace

    with TestClient(create_app(replace(settings, max_upload_bytes=20))) as client:
        response = client.post(
            f"/api/v1/projects/{project_id}/captures", files={"file": ("large", data)}
        )
        assert response.status_code == 413
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def prepared(repository, project_id, name="ordered.pcap"):
    stage = repository.safe_path(project_id, f".staging/{uuid4()}")
    stage.mkdir()
    source = stage / "source"
    shutil.copyfile(FIXTURES / name, source)
    capture_id = uuid4()
    index = stage / "packets.jsonl"
    packets = list(index_capture(source, capture_id, IndexSettings()))
    index.write_text("".join(p.model_dump_json() + "\n" for p in packets))
    return (
        project_id,
        capture_id,
        source,
        index,
        hashlib.sha256(source.read_bytes()).hexdigest(),
        "pcap",
        IndexSettings(),
        {"packet_count": len(packets), "diagnostics": {}},
    )


def test_concurrent_duplicate_publication_and_failed_transaction(storage):
    repository, _, _ = storage
    project = repository.create("Concurrent")
    first, second = prepared(repository, project.id), prepared(repository, project.id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda args: repository.finalize_import(*args), [first, second]))
    assert sorted(r["outcome"] for r in results) == ["already_imported", "imported"]
    assert results[0]["capture_id"] == results[1]["capture_id"]
    assert len(repository.captures(project.id, 0, 100)) == 1
    bad_project = repository.create("Rollback")
    bad = prepared(repository, bad_project.id)
    bad[3].write_text("not valid JSON\n")
    with pytest.raises(ValueError):
        repository.finalize_import(*bad)
    assert repository.captures(bad_project.id, 0, 100) == []
    # Retry reuses the checksum-verified immutable orphan source after rollback.
    retry = prepared(repository, bad_project.id)
    assert repository.finalize_import(*retry)["outcome"] == "imported"


def test_manifest_path_protection_and_integrity_detection(storage):
    repository, settings, _ = storage
    project = repository.create("Safety")
    with pytest.raises(StorageError):
        repository.safe_path(project.id, "../other")
    directory = repository.directory(project.id)
    (directory / "derived" / "escape").symlink_to(settings.project_root.parent)
    with pytest.raises(StorageError):
        repository.safe_path(project.id, "derived/escape/file")
    args = prepared(repository, project.id)
    result = repository.finalize_import(*args)
    capture = repository.get_capture(UUID(result["capture_id"]))
    source = repository.safe_path(project.id, capture.relative_path)
    source.chmod(0o644)
    source.write_bytes(b"tampered test source")
    with pytest.raises(StorageError, match="checksum"):
        repository.verify_source(capture.id)
    manifest = directory / "manifest.json"
    doc = json.loads(manifest.read_text())
    doc["format_version"] = 99
    manifest.write_text(json.dumps(doc))
    with pytest.raises(StorageError, match="incompatible"):
        repository.get(project.id)


def test_running_import_cancellation_and_publication_failure_cleanup(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Cancellation"}).json()["id"]
        job_id = upload(client, project_id)
        deadline = time.monotonic() + 5
        while client.get(f"/api/v1/jobs/{job_id}").json()["status"] == "queued":
            assert time.monotonic() < deadline
            time.sleep(0.005)
        # Spawn startup gives an opportunity to cancel before indexing publishes.
        response = client.post(f"/api/v1/jobs/{job_id}/cancel").json()
        assert response["status"] in {"cancelling", "cancelled"}
        assert finish(client, job_id)["status"] == "cancelled"
        assert repository.captures(UUID(project_id), 0, 100) == []
        # An incompatible manifest can appear after accepting the upload.
        client.app.state.jobs.max_workers = 0
        next_job = upload(client, project_id)
        manifest = settings.project_root / project_id / "manifest.json"
        old = manifest.read_text()
        doc = json.loads(old)
        doc["format_version"] = 99
        manifest.write_text(json.dumps(doc))
        client.app.state.jobs.max_workers = 2
        failed = finish(client, next_job)
        assert failed["status"] == "failed"
        assert "incompatible" in failed["error"]
        manifest.write_text(old)
        assert repository.captures(UUID(project_id), 0, 100) == []
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def reconstruct_job(client, capture_id, settings=None):
    response = client.post(f"/api/v1/captures/{capture_id}/reconstruct", json=settings or {})
    assert response.status_code == 202, response.text
    assert response.json()["kind"] == "tcp_reconstruction"
    return response.json()["id"]


def test_tcp_persistence_ranges_duplicates_observation_and_restart(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "TCP"}).json()["id"]
        capture_id = finish(client, upload(client, project_id, "tcp/gaps-overlaps.pcap"))["result"][
            "capture_id"
        ]
        assert client.get(f"/api/v1/captures/{capture_id}/sessions").status_code == 409
        job = finish(client, reconstruct_job(client, capture_id))
        assert job["status"] == "succeeded", job
        assert job["result"]["session_count"] == 1
        listed = client.get(f"/api/v1/captures/{capture_id}/sessions?limit=1").json()
        session = listed["items"][0]
        assert session["start_known"]
        assert client.get(f"/api/v1/sessions/{session['id']}").json() == session
        stream_id = session["streams"][0]["id"]
        assert client.get(f"/api/v1/streams/{stream_id}").json()["extent"] == 13
        full = client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=13").json()
        blocks = full["blocks"]
        conflict = next(b for b in blocks if b["status"] == "ambiguous")
        assert {v["data_hex"] for v in conflict["variants"]} == {b"D".hex(), b"X".hex()}
        assert all(not b["variants"] for b in blocks if b["status"] in {"gap", "truncated"})
        clipped = client.get(f"/api/v1/streams/{stream_id}/bytes?offset=1&length=2").json()
        variant = clipped["blocks"][0]["variants"][0]
        assert (
            "".join(block["variants"][0]["data_hex"] for block in clipped["blocks"]) == b"BC".hex()
        )
        capture = repository.get_capture(UUID(capture_id))
        raw = repository.safe_path(UUID(project_id), capture.relative_path).read_bytes()
        for block in blocks:
            for variant in block["variants"]:
                for evidence in variant["sources"]:
                    left = evidence["file_offset"]
                    size = block["byte_range"]["end"] - block["byte_range"]["start"]
                    assert raw[left : left + size].hex() == variant["data_hex"]
        for query in ["offset=12&length=2", "offset=-1&length=1", "offset=0&length=65537"]:
            assert client.get(f"/api/v1/streams/{stream_id}/bytes?{query}").status_code == 422
        anchor = {
            "stream_id": stream_id,
            "reconstruction_version": "tcp-v1",
            "byte_range": {"start": 2, "end": 5},
        }
        body = {"text": "Overlap is contradictory", "anchors": [anchor]}
        response = client.post(f"/api/v1/projects/{project_id}/observations", json=body)
        assert response.status_code == 201, response.text
        observation = response.json()
        assert len(observation["sources"]) >= 3
        assert "message_id" not in observation
        duplicate = finish(client, reconstruct_job(client, capture_id))
        assert duplicate["status"] == "succeeded", duplicate
        assert duplicate["result"]["outcome"] == "already_reconstructed"
        assert client.get(f"/api/v1/captures/{capture_id}/sessions").json()["items"] == [session]
        # Limits are persisted; changing settings must not silently rewrite immutable evidence.
        changed = finish(client, reconstruct_job(client, capture_id, {"max_spans_per_stream": 1}))
        assert changed["status"] == "failed"
        assert client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=13").json() == full
        other_id = client.post("/api/v1/projects", json={"name": "Other"}).json()["id"]
        assert (
            client.post(f"/api/v1/projects/{other_id}/observations", json=body).status_code == 422
        )
        body["anchors"][0]["reconstruction_version"] = "wrong"
        assert (
            client.post(f"/api/v1/projects/{project_id}/observations", json=body).status_code == 422
        )
    command.check(config)
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=13").json() == full
        assert client.get(f"/api/v1/projects/{project_id}/observations").json()["items"] == [
            observation
        ]
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def test_tcp_cancel_failure_isolation_and_integrity(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Safe TCP"}).json()["id"]
        capture_id = finish(client, upload(client, project_id, "tcp/isolated-ambiguous.pcap"))[
            "result"
        ]["capture_id"]
        client.app.state.jobs.max_workers = 0
        job_id = reconstruct_job(client, capture_id)
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelled"
        assert client.get(f"/api/v1/captures/{capture_id}/sessions").status_code == 409
        client.app.state.jobs.max_workers = 2
        result = finish(client, reconstruct_job(client, capture_id))
        assert result["status"] == "succeeded", result
        listed = client.get(f"/api/v1/captures/{capture_id}/sessions?limit=1").json()
        assert listed["next_offset"] == 1
        next_page = client.get(f"/api/v1/captures/{capture_id}/sessions?offset=1").json()
        assert next_page["items"][0]["diagnostics"]
        stream_id = listed["items"][0]["streams"][0]["id"]
        assert (
            client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=4").json()["blocks"][0][
                "variants"
            ][0]["data_hex"]
            == b"GOOD".hex()
        )
        capture = repository.get_capture(UUID(capture_id))
        source = repository.safe_path(UUID(project_id), capture.relative_path)
        source.chmod(0o644)
        source.write_bytes(source.read_bytes()[:-1] + b"Z")
        assert client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=4").status_code == 409
        failed = finish(client, reconstruct_job(client, capture_id))
        assert failed["status"] == "failed"
        assert client.get(f"/api/v1/captures/{capture_id}/sessions").status_code == 200
        assert client.get("/api/v1/health").status_code == 200
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def test_tcp_running_cancellation_preserves_previous_reconstruction(storage):
    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Repeat"}).json()["id"]
        capture_id = finish(client, upload(client, project_id, "tcp/ordered.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture_id))["status"] == "succeeded"
        previous = client.get(f"/api/v1/captures/{capture_id}/sessions").json()
        job_id = reconstruct_job(client, capture_id)
        deadline = time.monotonic() + 5
        while client.get(f"/api/v1/jobs/{job_id}").json()["status"] == "queued":
            assert time.monotonic() < deadline
            time.sleep(0.005)
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] in {
            "cancelling",
            "cancelled",
        }
        assert finish(client, job_id)["status"] == "cancelled"
        assert client.get(f"/api/v1/captures/{capture_id}/sessions").json() == previous
        assert client.get(f"/api/v1/jobs/{job_id}/events").text.count('"status":"cancelled"') == 1
    assert not list((settings.project_root / project_id / ".staging").iterdir())


def test_concurrent_tcp_publication_is_idempotent_and_source_lookup_works(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Concurrent TCP"}).json()["id"]
        capture_id = finish(client, upload(client, project_id, "tcp/ordered.pcap"))["result"][
            "capture_id"
        ]
        first, second = reconstruct_job(client, capture_id), reconstruct_job(client, capture_id)
        jobs = [finish(client, first), finish(client, second)]
        assert all(job["status"] == "succeeded" for job in jobs), jobs
        assert {job["result"]["outcome"] for job in jobs} == {
            "reconstructed",
            "already_reconstructed",
        }
        sessions = client.get(f"/api/v1/captures/{capture_id}/sessions").json()["items"]
        assert len(sessions) == 1
        assert "packet_ids" not in sessions[0] and sessions[0]["packet_count"] == 5
        stream_id = sessions[0]["streams"][0]["id"]
        evidence = client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=5").json()[
            "blocks"
        ][0]["variants"][0]["sources"][0]
        packet = client.get(f"/api/v1/packets/{evidence['packet_id']}").json()
        assert packet["index"] == evidence["packet_index"]
        assert packet["capture_id"] == capture_id
        capture = repository.get_capture(UUID(capture_id))
        raw = repository.safe_path(UUID(project_id), capture.relative_path).read_bytes()
        assert raw[evidence["file_offset"] : evidence["file_offset"] + 5] == b"HELLO"


def test_stage4_migration_preserves_populated_stage3_project(storage, monkeypatch):
    repository, settings, _ = storage
    schema = "pl_upgrade_" + uuid4().hex
    with repository.engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    url = make_url(settings.database_url).update_query_dict({"options": f"-csearch_path={schema}"})
    url = url.render_as_string(hide_password=False)
    engine = create_engine(url)
    try:
        with monkeypatch.context() as context:
            context.setenv("PROTOCOL_LAB_DATABASE_URL", url)
            config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
            command.upgrade(config, "0001_capture_storage")
            old = ProjectStore(engine, settings.project_root)
            project = old.create("Existing stage 3")
            capture_id = UUID(old.finalize_import(*prepared(old, project.id))["capture_id"])
            capture = old.get_capture(capture_id)
            source = old.safe_path(project.id, capture.relative_path)
            before = source.read_bytes()
            manifest = (old.directory(project.id) / "manifest.json").read_bytes()
            packets = old.packets(capture_id, 0, 100)
            command.upgrade(config, "head")
            command.check(config)
            assert old.get(project.id) == project
            assert old.get_capture(capture_id) == capture
            assert old.packets(capture_id, 0, 100) == packets
            assert source.read_bytes() == before
            assert (old.directory(project.id) / "manifest.json").read_bytes() == manifest
    finally:
        engine.dispose()
        with repository.engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def test_stage5_session_filters_packet_ranges_and_search_jobs(storage):
    _, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Investigate"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/reused-tuple.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        path = f"/api/v1/projects/{project}/sessions"
        sessions = client.get(path + "?limit=1").json()
        assert sessions["next_offset"] == 1
        session = sessions["items"][0]
        assert session["start_timestamp_ns"] is not None
        assert len(client.get(path + "?address=192.0.2.1&port=9000").json()["items"]) == 2
        assert client.get(path + "?port=9001").json()["items"] == []
        assert client.get(path + "?address=192.0.2.3").json()["items"] == []
        ns = session["end_timestamp_ns"]
        assert len(client.get(path + f"?end_ns={ns}").json()["items"]) == 1
        assert client.get(path + "?start_ns=10&end_ns=1").status_code == 422
        assert client.get(path + "?address=::1").status_code == 422
        stream_id = session["streams"][0]["id"]
        job = client.post(
            f"/api/v1/streams/{stream_id}/search", json={"pattern_hex": "4f4c"}
        ).json()
        result = finish(client, job["id"])
        assert result["status"] == "succeeded", result
        assert result["result"]["matches"] == [0]
        evidence = client.get(f"/api/v1/streams/{stream_id}/bytes?offset=0&length=2").json()[
            "blocks"
        ][0]["variants"][0]["sources"][0]
        packet_id = evidence["packet_id"]
        offset = evidence["packet_offset"]
        assert (
            client.get(f"/api/v1/packets/{packet_id}/bytes?offset={offset}&length=2").json()[
                "data_hex"
            ]
            == b"OL".hex()
        )
        assert (
            client.get(f"/api/v1/packets/{packet_id}/bytes?offset=0&length=4097").status_code == 422
        )
        client.app.state.jobs.max_workers = 0
        queued = client.post(
            f"/api/v1/streams/{stream_id}/search", json={"pattern_hex": "4f"}
        ).json()
        assert client.post(f"/api/v1/jobs/{queued['id']}/cancel").json()["status"] == "cancelled"
        assert client.get(f"/api/v1/streams/{stream_id}").status_code == 200
    command.check(config)


def test_stage5_log_mapping_clock_correlation_links_and_restart(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Clock"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/ordered.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream_id = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0][
            "streams"
        ][0]["id"]
        original = (FIXTURES / "actions/clock-offset.csv").read_bytes()
        mapping = {
            "timestamp_field": "when",
            "label_field": "operation",
            "parameters_field": "args",
            "timestamp_format": "unix_s",
        }
        route = f"/api/v1/projects/{project}/action-logs"
        preview = client.post(
            route + "/preview", files={"file": ("log.csv", original)}, data={"format": "csv"}
        )
        assert preview.json()["fields"] == ["when", "operation", "args"]

        def send_log():
            response = client.post(
                route,
                files={"file": ("log.csv", original)},
                data={"format": "csv", "mapping_json": json.dumps(mapping)},
            )
            assert response.status_code == 202, response.text
            return finish(client, response.json()["id"])

        job = send_log()
        assert job["status"] == "succeeded", job
        log_id = job["result"]["log_id"]
        log = client.get(route).json()["items"][0]
        assert log["event_count"] == 2 and log["rejected_rows"] == 1
        assert repository.safe_path(UUID(project), log["relative_path"]).read_bytes() == original
        correlation = f"/api/v1/streams/{stream_id}/actions?offset=0&length=10"
        assert client.get(correlation).json()["items"] == []
        updated = client.patch(
            f"/api/v1/action-logs/{log_id}/clock",
            json={"clock_offset_ns": "-1000000000", "expected_revision": 1},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["clock_revision"] == 2
        assert (
            client.patch(
                f"/api/v1/action-logs/{log_id}/clock",
                json={"clock_offset_ns": "0", "expected_revision": 1},
            ).status_code
            == 409
        )
        matched = client.get(correlation).json()
        assert (
            len(matched["items"]) == 1
            and matched["method"] == "time_window_only_not_semantic_proof"
        )
        event = matched["items"][0]
        assert event["timestamp_ns"] == "1700000001000126000"
        linked = client.post(
            f"/api/v1/projects/{project}/actions/{event['id']}/links",
            json={
                "text": "Manual evidence",
                "anchors": [
                    {
                        "stream_id": stream_id,
                        "reconstruction_version": "tcp-v1",
                        "byte_range": {"start": 0, "end": 5},
                    }
                ],
            },
        )
        assert linked.status_code == 201, linked.text
        link = linked.json()
        assert link["observation"]["sources"]
        assert send_log()["result"]["outcome"] == "already_imported"
        assert client.get(route).json()["items"][0]["clock_offset_ns"] == "-1000000000"
        other = client.post("/api/v1/projects", json={"name": "Other"}).json()["id"]
        assert (
            client.post(
                f"/api/v1/projects/{other}/actions/{event['id']}/links",
                json={
                    "text": "Wrong scope",
                    "anchors": [
                        {
                            "stream_id": stream_id,
                            "reconstruction_version": "tcp-v1",
                            "byte_range": {"start": 0, "end": 5},
                        }
                    ],
                },
            ).status_code
            == 422
        )
    with TestClient(create_app(settings)) as client:
        assert client.get(route).json()["items"][0]["clock_offset_ns"] == "-1000000000"
        assert client.get(f"/api/v1/projects/{project}/action-links").json()["items"] == [link]
        assert len(client.get(correlation).json()["items"]) == 1
    assert not list((settings.project_root / project / ".staging").iterdir())


def test_stage5_upgrade_backfills_times_without_rewriting_evidence(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Existing stage 4"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/ordered.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        path = f"/api/v1/captures/{capture}/sessions"
        before = client.get(path).json()
        stream = before["items"][0]["streams"][0]["id"]
        observation = client.post(
            f"/api/v1/projects/{project}/observations",
            json={
                "text": "Original evidence",
                "anchors": [
                    {
                        "stream_id": stream,
                        "reconstruction_version": "tcp-v1",
                        "byte_range": {"start": 0, "end": 5},
                    }
                ],
            },
        ).json()
        files = {
            str(p): p.read_bytes()
            for p in repository.directory(UUID(project)).rglob("*")
            if p.is_file()
        }
    # Reproduce a populated stage-4 schema only inside this fixture's disposable schema.
    with repository.engine.begin() as connection:
        for table in [
            "validation_results",
            "validation_runs",
            "corpus_versions",
            "hypothesis_versions",
            "interpretation_results",
            "interpretation_runs",
            "interpretation_versions",
            "framing_pieces",
            "framing_runs",
            "action_links",
            "actions",
            "action_logs",
        ]:
            connection.execute(text(f"DROP TABLE {table}"))
        connection.execute(
            text("ALTER TABLE tcp_sessions DROP COLUMN start_ns, DROP COLUMN end_ns")
        )
    command.stamp(config, "0002_tcp_reconstruction")
    command.upgrade(config, "head")
    command.check(config)
    with TestClient(create_app(settings)) as client:
        assert client.get(path).json() == before
        assert client.get(f"/api/v1/projects/{project}/observations").json()["items"] == [
            observation
        ]
    assert all(Path(path).read_bytes() == content for path, content in files.items())


def test_stage5_search_never_guesses_overlap_and_log_cancel_is_atomic(storage):
    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Incomplete"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/gaps-overlaps.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        for pattern, expected in [("414243", [0]), ("434445", []), ("434558", []), ("494a", [8])]:
            job = client.post(
                f"/api/v1/streams/{stream}/search", json={"pattern_hex": pattern}
            ).json()
            result = finish(client, job["id"])
            assert result["status"] == "succeeded", result
            assert result["result"]["matches"] == expected
            assert result["result"]["skipped_bytes"] == 7
        client.app.state.jobs.max_workers = 0
        route = f"/api/v1/projects/{project}/action-logs"
        job = client.post(
            route,
            files={"file": ("log.json", (FIXTURES / "actions/exact.json").read_bytes())},
            data={
                "format": "json",
                "mapping_json": json.dumps({"timestamp_field": "time", "label_field": "action"}),
            },
        ).json()
        assert client.post(f"/api/v1/jobs/{job['id']}/cancel").json()["status"] == "cancelled"
        assert client.get(route).json()["items"] == []
        assert not list((settings.project_root / project / ".staging").iterdir())


def test_stage6_framing_versions_coverage_provenance_observations_and_restart(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Framing"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/reordered-retransmitted.pcap"))[
            "result"
        ]["capture_id"]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        observation = client.post(
            f"/api/v1/projects/{project}/observations",
            json={
                "text": "Stable original bytes",
                "anchors": [
                    {
                        "stream_id": stream,
                        "reconstruction_version": "tcp-v1",
                        "byte_range": {"start": 2, "end": 7},
                    }
                ],
            },
        ).json()
        files = {
            str(p): p.read_bytes()
            for p in repository.directory(UUID(project)).rglob("*")
            if p.is_file()
        }
        route = f"/api/v1/streams/{stream}/framing"

        def run(spec):
            response = client.post(route, json=spec)
            assert response.status_code == 202, response.text
            result = finish(client, response.json()["id"])
            assert result["status"] == "succeeded", result
            return result["result"]

        first = run({"rule": {"kind": "fixed", "size": 7}})
        run_id = first["run_id"]
        meta = client.get(f"/api/v1/framing-runs/{run_id}").json()
        assert meta["message_count"] == 1 and meta["leftover_bytes"] == 3
        page = client.get(f"/api/v1/framing-runs/{run_id}/pieces?limit=1").json()
        assert page["next_offset"] == 1
        piece = page["items"][0]
        assert piece["anchor"]["byte_range"] == {"start": 0, "end": 7}
        assert piece["framing_version"] == run_id
        sources = client.get(f"/api/v1/streams/{stream}/bytes?offset=0&length=7").json()
        assert {
            s["packet_index"]
            for block in sources["blocks"]
            for v in block["variants"]
            for s in v["sources"]
        } >= {3, 4}
        duplicate = run({"rule": {"kind": "fixed", "size": 7}})
        assert duplicate["outcome"] == "already_framed" and duplicate["run_id"] == run_id
        second = run({"rule": {"kind": "fixed", "size": 5}})
        assert second["run_id"] != run_id
        assert client.get(f"/api/v1/framing-runs/{second['run_id']}").json()["message_count"] == 2
        assert len(client.get(route).json()["items"]) == 2
        assert client.get(f"/api/v1/framing-runs/{run_id}").json() == meta
        assert client.get(f"/api/v1/projects/{project}/observations").json()["items"] == [
            observation
        ]
        assert (
            client.post(
                route, json={"rule": {"kind": "manual", "ranges": [{"start": 0, "end": 11}]}}
            ).status_code
            == 422
        )
        client.app.state.jobs.max_workers = 0
        queued = client.post(route, json={"rule": {"kind": "fixed", "size": 2}}).json()
        assert client.post(f"/api/v1/jobs/{queued['id']}/cancel").json()["status"] == "cancelled"
        assert len(client.get(route).json()["items"]) == 2
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/framing-runs/{run_id}").json() == meta
        assert client.get(f"/api/v1/projects/{project}/observations").json()["items"] == [
            observation
        ]
    assert all(Path(path).read_bytes() == before for path, before in files.items())
    assert not list((settings.project_root / project / ".staging").iterdir())
    command.check(config)


def test_stage6_failed_framing_preserves_previous_results_and_unknown_payload(storage):
    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Framing incomplete"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/gaps-overlaps.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        path = f"/api/v1/streams/{stream}/framing"
        job = client.post(path, json={"rule": {"kind": "fixed", "size": 5}}).json()
        result = finish(client, job["id"])
        assert result["status"] == "succeeded", result
        run_id = result["result"]["run_id"]
        pieces = client.get(f"/api/v1/framing-runs/{run_id}/pieces").json()["items"]
        assert [p["data_status"] for p in pieces] == ["ambiguous", "incomplete", "incomplete"]
        failed = client.post(
            path, json={"rule": {"kind": "fixed", "size": 1}, "max_pieces": 1}
        ).json()
        assert finish(client, failed["id"])["status"] == "failed"
        assert len(client.get(path).json()["items"]) == 1
        assert client.get(f"/api/v1/framing-runs/{run_id}/pieces").json()["items"] == pieces


def test_stage6_upgrade_preserves_populated_stage5_research(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Stage 5 evidence"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/ordered.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        mapping = {
            "timestamp_field": "when",
            "label_field": "operation",
            "parameters_field": "args",
            "timestamp_format": "unix_s",
        }
        job = client.post(
            f"/api/v1/projects/{project}/action-logs",
            files={"file": ("actions.csv", (FIXTURES / "actions/clock-offset.csv").read_bytes())},
            data={"format": "csv", "mapping_json": json.dumps(mapping)},
        ).json()
        assert finish(client, job["id"])["status"] == "succeeded"
        event = client.get(f"/api/v1/projects/{project}/actions").json()["items"][0]
        linked = client.post(
            f"/api/v1/projects/{project}/actions/{event['id']}/links",
            json={
                "text": "Stable action evidence",
                "anchors": [
                    {
                        "stream_id": stream,
                        "reconstruction_version": "tcp-v1",
                        "byte_range": {"start": 0, "end": 5},
                    }
                ],
            },
        )
        assert linked.status_code == 201, linked.text
    tables = [
        "projects",
        "captures",
        "packets",
        "reconstructions",
        "tcp_sessions",
        "tcp_streams",
        "tcp_spans",
        "observations",
        "action_logs",
        "actions",
        "action_links",
    ]

    def snapshot():
        with repository.engine.connect() as connection:
            return {
                table: connection.execute(text(f"SELECT * FROM {table} ORDER BY id")).all()
                for table in tables
            }

    before = snapshot()
    files = {
        str(p): p.read_bytes()
        for p in repository.directory(UUID(project)).rglob("*")
        if p.is_file()
    }
    # Only this fixture's disposable schema; emulate stage 5 before the adding migration.
    with repository.engine.begin() as connection:
        for table in (
            "validation_results",
            "validation_runs",
            "corpus_versions",
            "hypothesis_versions",
            "interpretation_results",
            "interpretation_runs",
            "interpretation_versions",
            "framing_pieces",
            "framing_runs",
        ):
            connection.execute(text(f"DROP TABLE {table}"))
    command.stamp(config, "0003_investigation")
    command.upgrade(config, "head")
    command.check(config)
    assert snapshot() == before
    assert all(Path(path).read_bytes() == original for path, original in files.items())


def test_stage7_immutable_models_construct_results_provenance_and_restart(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Interpretation"}).json()["id"]
        capture = finish(client, upload(client, project, "framing/length-big.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        framing_spec = {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
        framed = finish(
            client, client.post(f"/api/v1/streams/{stream}/framing", json=framing_spec).json()["id"]
        )
        framing_id = framed["result"]["run_id"]
        document = dict(
            schema_version="interpretation-1",
            name="Payload",
            framing=framing_spec,
            fields=[
                dict(kind="int", name="n", width=2, signed=False, endian="big"),
                dict(kind="bytes", name="payload", length={"field": "n"}),
            ],
            checks=[dict(kind="length", field="payload", expected={"field": "n"})],
        )
        check = client.post(
            "/api/v1/interpretations/check", json={"document_json": json.dumps(document)}
        )
        assert check.json() == {"valid": True, "issues": []}
        model_path = f"/api/v1/projects/{project}/interpretations"
        response = client.post(model_path, json={"document_json": json.dumps(document)})
        assert response.status_code == 201, response.text
        version = response.json()
        assert (
            client.get("/api/v1/interpretations/schema").json()["$id"]
            == "urn:protocol-lab:interpretation-1"
        )
        files = {
            str(p): p.read_bytes()
            for p in repository.directory(UUID(project)).rglob("*")
            if p.is_file()
        }
        path = f"/api/v1/framing-runs/{framing_id}/interpretations"
        response = client.post(path, json={"version_id": version["id"]})
        assert response.status_code == 202, response.text
        completed = finish(client, response.json()["id"])
        assert completed["status"] == "succeeded", completed
        run_id = completed["result"]["run_id"]
        meta = client.get(f"/api/v1/interpretation-runs/{run_id}").json()
        assert meta["counts"] == {"passed": 3}
        summaries = client.get(f"/api/v1/interpretation-runs/{run_id}/results?limit=1").json()
        assert summaries["next_offset"] == 1
        assert "fields" not in summaries["items"][0]
        piece_id = summaries["items"][0]["piece_id"]
        result = client.get(f"/api/v1/interpretation-runs/{run_id}/results/{piece_id}").json()
        assert result["fields"][0]["value"] == "3"
        assert result["fields"][1]["anchor"]["byte_range"] == {"start": 2, "end": 5}
        source = client.get(f"/api/v1/streams/{stream}/bytes?offset=0&length=2").json()
        assert (
            len(
                {
                    s["packet_id"]
                    for b in source["blocks"]
                    for v in b["variants"]
                    for s in v["sources"]
                }
            )
            == 2
        )
        duplicate = finish(
            client, client.post(path, json={"version_id": version["id"]}).json()["id"]
        )
        assert duplicate["result"]["outcome"] == "already_interpreted"
        assert duplicate["result"]["run_id"] == run_id
        duplicate_version = client.post(
            model_path, json={"document_json": json.dumps(document), "parent_id": version["id"]}
        ).json()
        assert duplicate_version == version
        document["fields"][0]["constant"] = 3
        revised = client.post(
            model_path, json={"document_json": json.dumps(document), "parent_id": version["id"]}
        ).json()
        assert revised["id"] != version["id"] and revised["model_id"] == version["model_id"]
        assert revised["parent_id"] == version["id"]
        failure = finish(client, client.post(path, json={"version_id": revised["id"]}).json()["id"])
        assert failure["status"] == "succeeded", failure
        assert failure["result"]["counts"] == {"passed": 1, "failed": 2}
        assert client.get(f"/api/v1/interpretation-versions/{version['id']}").json() == version
        assert client.get(f"/api/v1/interpretation-runs/{run_id}").json() == meta
        client.app.state.jobs.max_workers = 0
        queued = client.post(path, json={"version_id": revised["id"]}).json()
        assert client.post(f"/api/v1/jobs/{queued['id']}/cancel").json()["status"] == "cancelled"
        assert len(client.get(path).json()["items"]) == 2
    with TestClient(create_app(settings)) as client:
        assert (
            client.get(f"/api/v1/interpretation-runs/{run_id}/results/{piece_id}").json() == result
        )
        assert client.get(f"/api/v1/interpretation-versions/{version['id']}").json() == version
    assert all(Path(p).read_bytes() == data for p, data in files.items())
    assert not list((settings.project_root / project / ".staging").iterdir())
    command.check(config)


def test_stage7_validation_scope_unknowns_and_failure_preserve_evidence(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Uncertain interpretation"}).json()[
            "id"
        ]
        capture = finish(client, upload(client, project, "tcp/gaps-overlaps.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        spec = {"rule": {"kind": "fixed", "size": 5}}
        framing_id = finish(
            client, client.post(f"/api/v1/streams/{stream}/framing", json=spec).json()["id"]
        )["result"]["run_id"]
        document = dict(
            schema_version="interpretation-1",
            name="Raw",
            framing=spec,
            fields=[dict(kind="bytes", name="raw", length="remaining")],
        )
        model_path = f"/api/v1/projects/{project}/interpretations"
        version = client.post(model_path, json={"document_json": json.dumps(document)}).json()
        path = f"/api/v1/framing-runs/{framing_id}/interpretations"
        completed = finish(
            client, client.post(path, json={"version_id": version["id"]}).json()["id"]
        )
        assert completed["status"] == "succeeded", completed
        summaries = client.get(
            f"/api/v1/interpretation-runs/{completed['result']['run_id']}/results"
        ).json()["items"]
        assert [r["status"] for r in summaries] == ["ambiguous", "unknown", "not_applicable"]
        assert summaries[0]["unknown_range_count"] > 0
        other = client.post("/api/v1/projects", json={"name": "Other"}).json()["id"]
        assert (
            client.post(
                f"/api/v1/projects/{other}/interpretations",
                json={"document_json": json.dumps(document), "parent_id": version["id"]},
            ).status_code
            == 422
        )
        foreign = client.post(
            f"/api/v1/projects/{other}/interpretations",
            json={"document_json": json.dumps(document)},
        ).json()
        assert client.post(path, json={"version_id": foreign["id"]}).status_code == 422
        document["framing"]["rule"]["size"] = 4
        mismatch = client.post(
            model_path, json={"document_json": json.dumps(document), "parent_id": version["id"]}
        ).json()
        assert client.post(path, json={"version_id": mismatch["id"]}).status_code == 422
        assert not list((settings.project_root / project / ".staging").iterdir())
        before = client.get(model_path).json()
        document["fields"][0]["length"] = "eval(1)"
        invalid = client.post(
            "/api/v1/interpretations/check", json={"document_json": json.dumps(document)}
        ).json()
        assert invalid["valid"] is False and invalid["issues"]
        assert (
            client.post(model_path, json={"document_json": json.dumps(document)}).status_code == 422
        )
        assert client.get(model_path).json() == before
        assert len(client.get(path).json()["items"]) == 1
    assert (
        repository.captures(UUID(project), 0, 100)[0].sha256
        == hashlib.sha256((FIXTURES / "tcp/gaps-overlaps.pcap").read_bytes()).hexdigest()
    )


def test_stage7_additive_migration_preserves_existing_framing(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Stage 6 project"}).json()["id"]
        capture = finish(client, upload(client, project, "framing/length-little.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        framed = finish(
            client,
            client.post(
                f"/api/v1/streams/{stream}/framing",
                json={"rule": {"kind": "length", "width": 2, "endian": "little", "adjustment": 2}},
            ).json()["id"],
        )
        assert framed["status"] == "succeeded"
    tables = [
        "projects",
        "captures",
        "packets",
        "reconstructions",
        "tcp_sessions",
        "tcp_streams",
        "tcp_spans",
        "observations",
        "action_logs",
        "actions",
        "action_links",
        "framing_runs",
        "framing_pieces",
    ]

    def snapshot():
        with repository.engine.connect() as db:
            return {
                table: db.execute(text(f"SELECT * FROM {table} ORDER BY id")).all()
                for table in tables
            }

    before = snapshot()
    files = {
        str(p): p.read_bytes()
        for p in repository.directory(UUID(project)).rglob("*")
        if p.is_file()
    }
    with repository.engine.begin() as db:
        for table in [
            "validation_results",
            "validation_runs",
            "corpus_versions",
            "hypothesis_versions",
            "interpretation_results",
            "interpretation_runs",
            "interpretation_versions",
        ]:
            db.execute(text(f"DROP TABLE {table}"))
    command.stamp(config, "0004_framing")
    command.upgrade(config, "head")
    command.check(config)
    assert snapshot() == before
    assert all(Path(p).read_bytes() == data for p, data in files.items())


def stage8_model(client, project, spec, constant=None, parent=None):
    field = dict(kind="int", name="n", width=2, signed=False, endian="big")
    if constant is not None:
        field["constant"] = constant
    document = dict(
        schema_version="interpretation-1",
        name="Corpus length",
        framing=spec,
        fields=[field, dict(kind="bytes", name="payload", length={"field": "n"})],
    )
    response = client.post(
        f"/api/v1/projects/{project}/interpretations",
        json={"document_json": json.dumps(document), "parent_id": parent},
    )
    assert response.status_code == 201, response.text
    return response.json()


def stage8_validate(client, project, corpus, version):
    response = client.post(
        f"/api/v1/projects/{project}/validation-runs",
        json={"corpus_version_id": corpus, "interpretation_version_id": version},
    )
    assert response.status_code == 202, response.text
    completed = finish(client, response.json()["id"])
    assert completed["status"] == "succeeded", completed
    return completed["result"]["run_id"]


def test_stage8_corpus_counterexample_versions_coverage_comparison_and_restart(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Corpus validation"}).json()["id"]
        captures = []
        for name in ["framing/length-big.pcap", "interpretation/arrays-new-parameters.pcap"]:
            capture = finish(client, upload(client, project, name))["result"]["capture_id"]
            assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
            captures.append(capture)
        spec = {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
        version = stage8_model(client, project, spec, constant=3)
        response = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={"name": "Two captures", "spec": {"capture_ids": captures, "direction": "a_to_b"}},
        )
        assert response.status_code == 201, response.text
        corpus = response.json()
        files = {
            str(p): p.read_bytes()
            for p in repository.directory(UUID(project)).rglob("*")
            if p.is_file()
        }
        first = stage8_validate(client, project, corpus["id"], version["id"])
        meta = client.get(f"/api/v1/validation-runs/{first}").json()
        coverage = meta["coverage"]
        assert (
            coverage["message_counts"]["passed"] == 1 and coverage["message_counts"]["failed"] == 3
        )
        assert coverage["stream_bytes"] == coverage["selected_stream_bytes"] == 21
        assert sum(coverage["byte_counts"].values()) == 21
        assert coverage["captures"] == 2 and len(meta["snapshot"]["sources"]) == 2
        assert client.get(f"/api/v1/validation-runs/{first}/currentness").json()["stale"] is False
        page = client.get(f"/api/v1/validation-runs/{first}/results?status=failed&limit=1").json()
        assert page["next_offset"] == 1 and "fields" not in page["items"][0]
        all_failed = client.get(f"/api/v1/validation-runs/{first}/results?status=failed").json()[
            "items"
        ]
        counterexample = next(r for r in all_failed if r["capture_id"] == captures[1])
        detail = client.get(
            f"/api/v1/validation-runs/{first}/results/{counterexample['id']}"
        ).json()
        assert detail["fields"][0]["value"] == "4"
        assert detail["fields"][0]["anchor"]["byte_range"] == {"start": 0, "end": 2}
        source = client.get(f"/api/v1/streams/{detail['stream_id']}/bytes?offset=0&length=2").json()
        assert "".join(v["data_hex"] for b in source["blocks"] for v in b["variants"]) == "0004"
        revised = stage8_model(client, project, spec, parent=version["id"])
        state = client.get(f"/api/v1/validation-runs/{first}/currentness").json()
        assert state["stale"] and "new_model_version" in state["reasons"]
        assert client.get(f"/api/v1/validation-runs/{first}").json() == meta
        second = stage8_validate(client, project, corpus["id"], revised["id"])
        second_meta = client.get(f"/api/v1/validation-runs/{second}").json()
        assert second_meta["coverage"]["message_counts"]["passed"] == 4
        comparison = client.get(f"/api/v1/validation-runs/{first}/compare/{second}?limit=1").json()
        assert comparison["counts"] == {"status": 3} and comparison["next_offset"] == 1
        assert comparison["same_sources"] is True
        repeat = stage8_validate(client, project, corpus["id"], revised["id"])
        assert (
            client.get(f"/api/v1/validation-runs/{second}/compare/{repeat}").json()["items"] == []
        )
        assert (
            client.get(f"/api/v1/validation-runs/{second}/compare/{repeat}").json()["counts"] == {}
        )
        filtered = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={
                "name": "Two captures",
                "parent_id": corpus["id"],
                "spec": {"capture_ids": captures, "port": 1},
            },
        ).json()
        assert (
            "new_corpus_version"
            in client.get(f"/api/v1/validation-runs/{second}/currentness").json()["reasons"]
        )
        third = stage8_validate(client, project, filtered["id"], revised["id"])
        filtered_meta = client.get(f"/api/v1/validation-runs/{third}").json()["coverage"]
        assert (
            filtered_meta["selected_stream_bytes"] == 0
            and filtered_meta["excluded_stream_bytes"] == 21
        )
        assert filtered_meta["byte_counts"]["not_applicable"] == 21
        summary = client.get(f"/api/v1/projects/{project}/validation-runs?limit=1").json()
        assert summary["next_offset"] == 1 and "snapshot" not in summary["items"][0]
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/validation-runs/{first}").json() == meta
        assert (
            client.get(f"/api/v1/validation-runs/{first}/results/{counterexample['id']}").json()
            == detail
        )
    assert all(Path(p).read_bytes() == data for p, data in files.items())
    assert not list((settings.project_root / project / ".staging").iterdir())
    command.check(config)


def test_stage8_uncovered_missing_reconstruction_and_source_change_are_explicit(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Uncovered corpus"}).json()["id"]
        captures = []
        for name in ["framing/length-incomplete.pcap", "unsupported-link.pcap", "tcp/ordered.pcap"]:
            captures.append(finish(client, upload(client, project, name))["result"]["capture_id"])
        for capture in captures[:2]:
            assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        version = stage8_model(
            client, project, {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
        )
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={"name": "Coverage", "spec": {"capture_ids": captures}},
        ).json()
        run = stage8_validate(client, project, corpus["id"], version["id"])
        meta = client.get(f"/api/v1/validation-runs/{run}").json()
        assert meta["coverage"]["captures_without_reconstruction"] == 1
        assert meta["coverage"]["unframed_bytes"] == 3
        assert meta["coverage"]["stream_bytes"] == 8
        assert meta["coverage"]["counts"]["unknown"] >= 2
        assert meta["coverage"]["noneligible_packets"] >= 1
        assert finish(client, reconstruct_job(client, captures[2]))["status"] == "succeeded"
        state = client.get(f"/api/v1/validation-runs/{run}/currentness").json()
        assert "source_or_reconstruction_changed_or_unavailable" in state["reasons"]
        assert client.get(f"/api/v1/validation-runs/{run}").json() == meta
        # Mutate only this disposable test source, then restore its original bytes.
        capture = repository.get_capture(UUID(captures[0]))
        path = repository.safe_path(UUID(project), capture.relative_path)
        original = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(original[:-1])
        failed = client.post(
            f"/api/v1/projects/{project}/validation-runs",
            json={"corpus_version_id": corpus["id"], "interpretation_version_id": version["id"]},
        ).json()
        assert finish(client, failed["id"])["status"] == "failed"
        assert len(client.get(f"/api/v1/projects/{project}/validation-runs").json()["items"]) == 1
        path.write_bytes(original)
        path.chmod(0o444)
    assert not list((settings.project_root / project / ".staging").iterdir())


def test_stage8_hypothesis_evidence_scope_cancellation_and_cross_project_guards(storage):
    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Hypotheses"}).json()["id"]
        other = client.post("/api/v1/projects", json={"name": "Other"}).json()["id"]
        capture = finish(client, upload(client, project, "framing/length-big.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        observation = client.post(
            f"/api/v1/projects/{project}/observations",
            json={
                "text": "Header n=3 for ABC",
                "anchors": [
                    {
                        "stream_id": stream,
                        "reconstruction_version": "tcp-v1",
                        "byte_range": {"start": 0, "end": 2},
                    }
                ],
            },
        ).json()
        body = {
            "statement": "n is the number of payload bytes",
            "rationale": "Observed byte counts",
            "scope": "Selected direction; not established for all devices",
            "observation_ids": [observation["id"]],
            "unknowns": ["Other commands"],
            "contradictions": [],
        }
        response = client.post(f"/api/v1/projects/{project}/hypotheses", json=body)
        assert response.status_code == 201, response.text
        hypothesis = response.json()
        assert client.get(f"/api/v1/hypotheses/{hypothesis['id']}/evidence").json()["items"] == [
            observation
        ]
        body["parent_id"] = hypothesis["id"]
        body["contradictions"] = ["A future capture might disagree"]
        revised = client.post(f"/api/v1/projects/{project}/hypotheses", json=body).json()
        assert (
            revised["hypothesis_id"] == hypothesis["hypothesis_id"]
            and revised["id"] != hypothesis["id"]
        )
        assert client.get(f"/api/v1/hypotheses/{hypothesis['id']}").json() == hypothesis
        assert client.post(f"/api/v1/projects/{other}/hypotheses", json=body).status_code == 422
        body.pop("parent_id")
        assert client.post(f"/api/v1/projects/{other}/hypotheses", json=body).status_code == 422
        assert (
            client.post(
                f"/api/v1/projects/{other}/corpora",
                json={"name": "Foreign", "spec": {"capture_ids": [capture]}},
            ).status_code
            == 422
        )
        version = stage8_model(
            client, project, {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
        )
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={"name": "Own", "spec": {"capture_ids": [capture]}},
        ).json()
        assert (
            client.post(
                f"/api/v1/projects/{other}/validation-runs",
                json={
                    "corpus_version_id": corpus["id"],
                    "interpretation_version_id": version["id"],
                },
            ).status_code
            == 422
        )
        client.app.state.jobs.max_workers = 0
        queued = client.post(
            f"/api/v1/projects/{project}/validation-runs",
            json={"corpus_version_id": corpus["id"], "interpretation_version_id": version["id"]},
        ).json()
        assert client.post(f"/api/v1/jobs/{queued['id']}/cancel").json()["status"] == "cancelled"
        assert client.get(f"/api/v1/projects/{project}/validation-runs").json()["items"] == []
        assert not list((settings.project_root / project / ".staging").iterdir())
        assert client.get(f"/api/v1/projects/{project}/observations").json()["items"] == [
            observation
        ]
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/hypotheses/{revised['id']}").json() == revised


def test_stage8_additive_migration_preserves_populated_stage7_project(storage):
    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Stage 7 project"}).json()["id"]
        capture = finish(client, upload(client, project, "framing/length-big.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        spec = {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
        framed = finish(
            client, client.post(f"/api/v1/streams/{stream}/framing", json=spec).json()["id"]
        )["result"]["run_id"]
        version = stage8_model(client, project, spec)
        assert (
            finish(
                client,
                client.post(
                    f"/api/v1/framing-runs/{framed}/interpretations",
                    json={"version_id": version["id"]},
                ).json()["id"],
            )["status"]
            == "succeeded"
        )
    tables = [
        "projects",
        "captures",
        "packets",
        "reconstructions",
        "tcp_sessions",
        "tcp_streams",
        "tcp_spans",
        "observations",
        "action_logs",
        "actions",
        "action_links",
        "framing_runs",
        "framing_pieces",
        "interpretation_versions",
        "interpretation_runs",
        "interpretation_results",
    ]

    def snapshot():
        with repository.engine.connect() as db:
            return {
                table: db.execute(text(f"SELECT * FROM {table} ORDER BY id")).all()
                for table in tables
            }

    before = snapshot()
    files = {
        str(p): p.read_bytes()
        for p in repository.directory(UUID(project)).rglob("*")
        if p.is_file()
    }
    with repository.engine.begin() as db:
        for table in [
            "validation_results",
            "validation_runs",
            "corpus_versions",
            "hypothesis_versions",
        ]:
            db.execute(text(f"DROP TABLE {table}"))
    command.stamp(config, "0005_interpretations")
    command.upgrade(config, "head")
    command.check(config)
    assert snapshot() == before
    assert all(Path(p).read_bytes() == data for p, data in files.items())


def test_stage8_bad_framing_does_not_block_another_capture_and_uncertainty_is_counted(storage):
    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Partial validation"}).json()["id"]
        captures = []
        for name in ["framing/length-big.pcap", "interpretation/arrays-new-parameters.pcap"]:
            capture = finish(client, upload(client, project, name))["result"]["capture_id"]
            assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
            captures.append(capture)
        version = stage8_model(
            client,
            project,
            {"rule": {"kind": "length", "width": 2, "adjustment": 2}, "max_pieces": 1},
        )
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={"name": "Partial", "spec": {"capture_ids": captures}},
        ).json()
        run = stage8_validate(client, project, corpus["id"], version["id"])
        meta = client.get(f"/api/v1/validation-runs/{run}").json()
        assert meta["coverage"]["byte_counts"]["unknown"] == 15
        assert meta["coverage"]["message_counts"]["passed"] == 1
        assert meta["coverage"]["stream_bytes"] == 21
        capture = finish(client, upload(client, project, "tcp/gaps-overlaps.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        doc = dict(
            schema_version="interpretation-1",
            name="Raw",
            framing={"rule": {"kind": "fixed", "size": 5}},
            fields=[dict(kind="bytes", name="raw", length="remaining")],
        )
        raw = client.post(
            f"/api/v1/projects/{project}/interpretations", json={"document_json": json.dumps(doc)}
        ).json()
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={"name": "Uncertain", "spec": {"capture_ids": [capture]}},
        ).json()
        run = stage8_validate(client, project, corpus["id"], raw["id"])
        coverage = client.get(f"/api/v1/validation-runs/{run}").json()["coverage"]
        assert coverage["ambiguous_source_bytes"] > 0 and coverage["unavailable_source_bytes"] > 0
        assert coverage["counts"]["ambiguous"] > 0 and coverage["counts"]["unknown"] > 0
        assert sum(coverage["byte_counts"].values()) == coverage["stream_bytes"]


# Stage 9 tests keep both source and destination in independently migrated, test-owned schemas.
def destination_store(storage, tmp_path, monkeypatch):
    from contextlib import contextmanager

    @contextmanager
    def isolated():
        _, settings, _ = storage
        schema = "pl_restore_" + uuid4().hex
        admin = create_engine(os.environ["PROTOCOL_LAB_TEST_DATABASE_URL"])
        with admin.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        url = (
            make_url(settings.database_url)
            .update_query_dict({"options": f"-csearch_path={schema}"})
            .render_as_string(hide_password=False)
        )
        with monkeypatch.context() as change:
            change.setenv("PROTOCOL_LAB_DATABASE_URL", url)
            config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
            command.upgrade(config, "head")
        engine = create_engine(url)
        root = tmp_path / ("moved-" + schema)
        try:
            yield ProjectStore(engine, root), Settings(database_url=url, project_root=root)
        finally:
            engine.dispose()
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            admin.dispose()

    return isolated()


def stage9_research(client):
    project = client.post("/api/v1/projects", json={"name": "Portable research"}).json()["id"]
    capture = finish(client, upload(client, project, "framing/length-big.pcap"))["result"][
        "capture_id"
    ]
    assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
    stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][0][
        "id"
    ]
    anchor = {
        "stream_id": stream,
        "reconstruction_version": "tcp-v1",
        "byte_range": {"start": 0, "end": 2},
    }
    observation = client.post(
        f"/api/v1/projects/{project}/observations",
        json={"text": "Header from original bytes", "anchors": [anchor]},
    ).json()
    hypothesis_body = {
        "statement": "Length in bytes",
        "rationale": "Observed examples",
        "scope": "Selected TCP direction",
        "observation_ids": [observation["id"]],
        "unknowns": ["Other commands"],
        "contradictions": [],
    }
    hypothesis = client.post(f"/api/v1/projects/{project}/hypotheses", json=hypothesis_body).json()
    client.post(
        f"/api/v1/projects/{project}/hypotheses",
        json={
            **hypothesis_body,
            "parent_id": hypothesis["id"],
            "unknowns": ["Other commands", "Device versions"],
        },
    )
    log_response = client.post(
        f"/api/v1/projects/{project}/action-logs",
        files={"file": ("actions.csv", (FIXTURES / "actions/clock-offset.csv").read_bytes())},
        data={
            "format": "csv",
            "mapping_json": json.dumps(
                {
                    "timestamp_field": "when",
                    "label_field": "operation",
                    "parameters_field": "args",
                    "timestamp_format": "unix_s",
                    "delimiter": ",",
                }
            ),
        },
    )
    # Use the fixture's documented mapping, including exact nanosecond clock adjustment.
    assert log_response.status_code == 202, log_response.text
    log_job = finish(client, log_response.json()["id"])
    assert log_job["status"] == "succeeded", log_job
    log = client.get(f"/api/v1/projects/{project}/action-logs").json()["items"][0]
    action = client.get(f"/api/v1/projects/{project}/actions").json()["items"][0]
    clock = client.patch(
        f"/api/v1/action-logs/{log['id']}/clock",
        json={"clock_offset_ns": "123456789012345", "expected_revision": 1},
    )
    assert clock.status_code == 200, clock.text
    link = client.post(
        f"/api/v1/projects/{project}/actions/{action['id']}/links",
        json={"text": "Linked evidence", "anchors": [anchor]},
    )
    assert link.status_code == 201, link.text
    spec = {"rule": {"kind": "length", "width": 2, "adjustment": 2}}
    first_model = stage8_model(client, project, spec, constant=3)
    framed = finish(
        client, client.post(f"/api/v1/streams/{stream}/framing", json=spec).json()["id"]
    )
    assert framed["status"] == "succeeded", framed
    framing_id = framed["result"]["run_id"]
    parsed = client.post(
        f"/api/v1/framing-runs/{framing_id}/interpretations", json={"version_id": first_model["id"]}
    )
    assert parsed.status_code == 202, parsed.text
    assert finish(client, parsed.json()["id"])["status"] == "succeeded"
    corpus = client.post(
        f"/api/v1/projects/{project}/corpora",
        json={"name": "Selected corpus", "spec": {"capture_ids": [capture]}},
    ).json()
    first = stage8_validate(client, project, corpus["id"], first_model["id"])
    revised = stage8_model(client, project, spec, parent=first_model["id"])
    second = stage8_validate(client, project, corpus["id"], revised["id"])
    revised_corpus = client.post(
        f"/api/v1/projects/{project}/corpora",
        json={
            "name": "Selected corpus",
            "parent_id": corpus["id"],
            "spec": {"capture_ids": [capture], "direction": "a_to_b"},
        },
    ).json()
    assert revised_corpus["id"] != corpus["id"]
    return project, capture, stream, first_model, first, second, log, observation


def stage9_operation(client, project, operation):
    response = client.post(f"/api/v1/projects/{project}/operations/{operation}", json={})
    assert response.status_code == 202, response.text
    job = finish(client, response.json()["id"])
    assert job["status"] == "succeeded", json.dumps(job)
    return job["result"]


def test_stage9_full_snapshot_archive_restore_without_old_directory(storage, tmp_path, monkeypatch):
    from protocol_lab.storage.portable import TABLES, pack, snapshot, verify_bundle

    repository, settings, config = storage
    with TestClient(create_app(settings)) as client:
        project, capture, stream, model, first, second, log, observation = stage9_research(client)
        # Unrelated research must never enter this project's snapshot.
        other = client.post("/api/v1/projects", json={"name": "Unrelated private research"}).json()[
            "id"
        ]
        finish(client, upload(client, other))
        paths = [
            f"/projects/{project}",
            f"/captures/{capture}",
            f"/captures/{capture}/packets",
            f"/captures/{capture}/sessions",
            f"/streams/{stream}/bytes?offset=0&length=8",
            f"/projects/{project}/observations",
            f"/projects/{project}/action-logs",
            f"/projects/{project}/actions",
            f"/projects/{project}/action-links",
            f"/projects/{project}/hypotheses",
            f"/projects/{project}/corpora",
            f"/projects/{project}/interpretations",
            f"/validation-runs/{first}",
            f"/validation-runs/{first}/results",
            f"/validation-runs/{second}",
            f"/validation-runs/{first}/compare/{second}",
        ]
        before = {}
        for path in paths:
            response = client.get("/api/v1" + path)
            assert response.status_code == 200, (path, response.text)
            before[path] = response.json()
        saved = stage9_operation(client, project, "save")
        checkpoint = repository.directory(UUID(project)) / saved["checkpoint"]
        bundle = verify_bundle(checkpoint)
        assert all(bundle.table_counts[name] > 0 for name in TABLES), bundle.table_counts
        exported = stage9_operation(client, project, "export")
        archive_response = client.get(exported["download_url"])
        assert archive_response.status_code == 200
        archive = tmp_path / "moved-project.zip"
        archive.write_bytes(archive_response.content)
        report_result = stage9_operation(client, project, "report")
        report = client.get(report_result["download_url"]).text
        assert "Основания: Observed examples" in report and "Друг" not in report
        assert "#### failed — 2 результатов" in report and "File offset" in report
        assert "Other commands" in report and "контрпримеры" in report
        assert repository.get_capture(UUID(capture)).sha256 in report
        assert stage9_operation(client, project, "verify")["outcome"] == "verified"
    # Physically make the original inaccessible; destination has a separate DB schema and root.
    old_root = settings.project_root.with_name("unavailable-original")
    settings.project_root.rename(old_root)
    try:
        with destination_store(storage, tmp_path, monkeypatch) as (
            destination,
            destination_settings,
        ):
            with TestClient(create_app(destination_settings)) as client:
                response = client.post(
                    "/api/v1/projects/restore",
                    files={"file": ("untrusted/../../archive.zip", archive.read_bytes())},
                )
                assert response.status_code == 202
                result = finish(client, response.json()["id"])
                assert result["status"] == "succeeded", result
                assert result["result"]["project_id"] == project
                for path in paths:
                    assert client.get("/api/v1" + path).json() == before[path], path
                assert client.get(f"/api/v1/validation-runs/{first}/currentness").json()["stale"]
                assert stage9_operation(client, project, "verify")["outcome"] == "verified"
                # Reimporting the same original preserves capture identity and attached research.
                duplicate = finish(client, upload(client, project, "framing/length-big.pcap"))
                assert duplicate["result"]["outcome"] == "already_imported"
                repeated = client.post(
                    "/api/v1/projects/restore", files={"file": ("x.zip", archive.read_bytes())}
                )
                failed = finish(client, repeated.json()["id"])
                assert failed["status"] == "failed" and failed["result"] is None
                assert "already exists" in failed["error"]
                assert len(client.get("/api/v1/projects").json()["items"]) == 1
            with TestClient(create_app(destination_settings)) as client:
                assert (
                    client.get(f"/api/v1/streams/{stream}/bytes?offset=0&length=8").json()
                    == before[f"/streams/{stream}/bytes?offset=0&length=8"]
                )
                assert client.get(report_result["download_url"]).status_code == 404
                assert client.get(f"/api/v1/projects/{other}").status_code == 404
                rebuilt = tmp_path / "restored-snapshot"
                snapshot(destination, UUID(project), rebuilt)
                assert verify_bundle(rebuilt).table_counts == bundle.table_counts
                pack(rebuilt, tmp_path / "restored-again.zip")
    finally:
        old_root.rename(settings.project_root)
    command.check(config)


def test_stage9_gui_cli_values_diagnostics_and_export_model(storage, tmp_path):
    import io

    from protocol_lab.interpretation.schema import ProtocolModel
    from protocol_lab.services.application import apply_capture

    _, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "GUI CLI parity"}).json()["id"]
        for name in [
            "framing/length-big.pcap",
            "tcp/gaps-overlaps.pcap",
            "mixed-diagnostics.pcap",
            "multi-interface.pcapng",
            "unsupported-link.pcap",
            "tcp/isolated-ambiguous.pcap",
            "tcp/conflicting-server-syn.pcap",
        ]:
            capture = finish(client, upload(client, project, name))["result"]["capture_id"]
            assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
            document = dict(
                schema_version="interpretation-1",
                name="Raw",
                framing={"rule": {"kind": "fixed", "size": 5}},
                fields=[dict(kind="bytes", name="raw", length="remaining")],
            )
            version = client.post(
                f"/api/v1/projects/{project}/interpretations",
                json={"document_json": json.dumps(document)},
            ).json()
            downloaded = client.get(f"/api/v1/interpretation-versions/{version['id']}/export")
            assert (
                downloaded.status_code == 200
                and downloaded.json()
                == ProtocolModel.model_validate(document).model_dump(mode="json")
            )
            corpus = client.post(
                f"/api/v1/projects/{project}/corpora",
                json={"name": name, "spec": {"capture_ids": [capture]}},
            ).json()
            run = stage8_validate(client, project, corpus["id"], version["id"])
            exported = finish(
                client, client.post(f"/api/v1/validation-runs/{run}/export").json()["id"]
            )
            assert exported["status"] == "succeeded", exported
            gui = client.get(exported["result"]["download_url"]).json()
            output = io.StringIO()
            apply_capture(
                ProtocolModel.model_validate_json(downloaded.text),
                FIXTURES / name,
                output,
                capture_id=UUID(capture),
            )
            cli = json.loads(output.getvalue())

            def facts(value):
                return sorted(
                    json.dumps(
                        {key: field for key, field in item.items() if key not in {"id"}},
                        sort_keys=True,
                    )
                    for item in value["results"]
                )

            assert facts(gui) == facts(cli), name
            assert gui["run"]["coverage"] == cli["run"]["coverage"], name


def test_unreconstructed_directions_publication_scope_restart_and_restore(
    storage, tmp_path, monkeypatch
):
    from protocol_lab.storage.portable import restore, snapshot
    from protocol_lab.storage.validation import ValidationStore

    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project = client.post("/api/v1/projects", json={"name": "Incomplete corpus"}).json()["id"]
        capture = finish(client, upload(client, project, "tcp/isolated-ambiguous.pcap"))["result"][
            "capture_id"
        ]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        doc = dict(
            schema_version="interpretation-1",
            name="Raw",
            framing={"rule": {"kind": "fixed", "size": 4}},
            fields=[dict(kind="bytes", name="raw", length="remaining")],
        )
        version = client.post(
            f"/api/v1/projects/{project}/interpretations",
            json={"document_json": json.dumps(doc)},
        ).json()
        runs = []
        for filters, expected in [({}, 1), ({"direction": "b_to_a"}, 0), ({"port": 1}, 0)]:
            corpus = client.post(
                f"/api/v1/projects/{project}/corpora",
                json={"name": "Scope", "spec": {"capture_ids": [capture], **filters}},
            ).json()
            run = stage8_validate(client, project, corpus["id"], version["id"])
            runs.append(run)
            meta = client.get(f"/api/v1/validation-runs/{run}").json()
            assert meta["coverage"]["unreconstructed_directions"] == expected
            assert meta["coverage"]["excluded_unreconstructed_directions"] == 1 - expected
            rows = client.get(f"/api/v1/validation-runs/{run}/results").json()["items"]
            (summary,) = [row for row in rows if row["kind"] == "reconstruction_diagnostic"]
            item = client.get(f"/api/v1/validation-runs/{run}/results/{summary['id']}").json()
            assert item["status"] == ("unknown" if expected else "not_applicable")
            assert item["direction"] == "a_to_b" and item["anchor"] is None
            assert item["stream_id"] is None
            assert client.get(f"/api/v1/sessions/{item['session_id']}").status_code == 200
        comparison = client.get(f"/api/v1/validation-runs/{runs[0]}/compare/{runs[1]}").json()
        assert any(
            row["change"] == "status" and row["left"]["kind"] == "reconstruction_diagnostic"
            for row in comparison["items"]
        )
        before = client.get(f"/api/v1/validation-runs/{runs[0]}").json()
    with TestClient(create_app(settings)) as client:
        assert client.get(f"/api/v1/validation-runs/{runs[0]}").json() == before
    bundle = tmp_path / "bundle"
    snapshot(repository, UUID(project), bundle)
    with destination_store(storage, tmp_path, monkeypatch) as (destination, restored_settings):
        restore(destination, bundle)
        with TestClient(create_app(restored_settings)) as client:
            assert client.get(f"/api/v1/validation-runs/{runs[0]}").json() == before
    # Publication must reject an artifact that drops this mandatory unknown diagnosis.
    store = ValidationStore(repository)
    original = store.get(UUID(runs[0]))
    from protocol_lab.validation.engine import CoverageCounter, item_id
    from protocol_lab.validation.models import RunInput, ValidationRun

    frozen = store.freeze(
        UUID(project),
        RunInput(
            corpus_version_id=original.snapshot.corpus.id,
            interpretation_version_id=original.snapshot.interpretation_version_id,
        ),
    )
    omitted = tmp_path / "omitted.jsonl"
    items = []
    counter = CoverageCounter(frozen)
    for summary in store.results(original.snapshot.id, 0, 100):
        if summary.kind == "reconstruction_diagnostic":
            continue
        item = store.result(original.snapshot.id, summary.id)
        item = item.model_copy(
            update={
                "id": item_id(
                    frozen.id,
                    item.capture_id,
                    item.anchor,
                    item.kind,
                    item.stream_id,
                    item.session_id,
                    item.direction,
                )
            }
        )
        items.append(item)
        counter.add(item)
    omitted.write_text(
        ValidationRun(snapshot=frozen, coverage=counter.result()).model_dump_json()
        + "\n"
        + "".join(item.model_dump_json() + "\n" for item in items)
    )
    with pytest.raises(StorageError, match="entire selected corpus"):
        store.publish(frozen, omitted, {})


def test_stage9_checksum_cancellation_invalid_snapshot_and_rollback(storage, tmp_path, monkeypatch):
    from protocol_lab.storage.portable import pack, restore, snapshot

    repository, settings, _ = storage
    project = repository.create("Integrity")
    args = prepared(repository, project.id)
    repository.finalize_import(*args)
    shutil.rmtree(args[2].parent)
    checkpoint = tmp_path / "snapshot"
    bundle = snapshot(repository, project.id, checkpoint)
    capture = repository.get_capture(args[1])
    source = repository.safe_path(project.id, capture.relative_path)
    original = source.read_bytes()
    source.chmod(0o600)
    source.write_bytes(original[:-1])
    with TestClient(create_app(settings)) as client:
        response = client.post(f"/api/v1/projects/{project.id}/operations/verify")
        failed = finish(client, response.json()["id"])
        assert failed["status"] == "failed" and failed["result"] is None
        assert "checksum" in failed["error"]
        client.app.state.jobs.max_workers = 0
        queued = client.post(f"/api/v1/projects/{project.id}/operations/export").json()
        assert client.post(f"/api/v1/jobs/{queued['id']}/cancel").json()["status"] == "cancelled"
    assert not list(repository.safe_path(project.id, ".staging").iterdir())
    source.write_bytes(original)
    source.chmod(0o444)
    # Valid ZIP checksums are not enough: wrong FK scopes must roll back all inserted rows/files.
    lines = (checkpoint / "metadata.jsonl").read_text().splitlines()
    entries = [json.loads(line) for line in lines]
    next(v for v in entries if v["table"] == "packets")["row"]["capture_id"] = str(uuid4())
    metadata = checkpoint / "metadata.jsonl"
    metadata.write_text("".join(json.dumps(v) + "\n" for v in entries))
    value = bundle.model_dump(mode="json")
    value["members"]["metadata.jsonl"] = {
        "size_bytes": metadata.stat().st_size,
        "sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
    }
    (checkpoint / "bundle.json").write_text(json.dumps(value))
    with destination_store(storage, tmp_path, monkeypatch) as (destination, dest_settings):
        with pytest.raises((StorageError, ValueError)):
            restore(destination, checkpoint)
        assert destination.list_projects(0, 100) == []
        assert not destination.directory(project.id).exists()
        archive = tmp_path / "invalid.zip"
        pack(checkpoint, archive)
        with TestClient(create_app(dest_settings)) as client:
            response = client.post(
                "/api/v1/projects/restore", files={"file": ("bad.zip", archive.read_bytes())}
            )
            failed = finish(client, response.json()["id"])
            assert failed["status"] == "failed" and failed["result"] is None
            assert destination.list_projects(0, 100) == []


def test_stage9_cli_project_commands_and_consistent_clock_snapshot(storage, tmp_path, monkeypatch):
    from sqlalchemy import update

    from protocol_lab.cli.main import main
    from protocol_lab.storage import portable
    from protocol_lab.storage.database import ActionLogRow

    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project, capture, stream, model, first, second, log, observation = stage9_research(client)
    monkeypatch.setenv("PROTOCOL_LAB_PROJECT_ROOT", str(settings.project_root))
    checkpoint = tmp_path / "cli-checkpoint"
    changed = False
    original_copy = portable.copy_checked

    def update_during_copy(*args, **kwargs):
        nonlocal changed
        if not changed:
            changed = True
            with repository.engine.begin() as conn:
                conn.execute(
                    update(ActionLogRow)
                    .where(ActionLogRow.id == UUID(log["id"]))
                    .values(clock_offset_ns=-1000000000, clock_revision=3)
                )
        return original_copy(*args, **kwargs)

    with monkeypatch.context() as change:
        change.setattr(portable, "copy_checked", update_during_copy)
        assert main(["project", "save", "--project-id", project, "--output", str(checkpoint)]) == 0
    bundle = portable.verify_bundle(checkpoint)
    logs = [row for name, row in portable.rows(checkpoint) if name == "action_logs"]
    assert int(logs[0]["clock_offset_ns"]) == 123456789012345 and logs[0]["clock_revision"] == 2
    assert main(["project", "verify", "--directory", str(checkpoint)]) == 0
    assert main(["project", "save", "--project-id", project, "--output", str(checkpoint)]) == 2
    archive = tmp_path / "cli-project.zip"
    assert main(["project", "export", "--project-id", project, "--output", str(archive)]) == 0
    before = archive.read_bytes()
    assert main(["project", "export", "--project-id", project, "--output", str(archive)]) == 2
    assert archive.read_bytes() == before
    with destination_store(storage, tmp_path, monkeypatch) as (destination, dest_settings):
        with monkeypatch.context() as change:
            change.setenv("PROTOCOL_LAB_DATABASE_URL", dest_settings.database_url)
            change.setenv("PROTOCOL_LAB_PROJECT_ROOT", str(dest_settings.project_root))
            assert main(["project", "restore", "--directory", str(checkpoint)]) == 0
            assert main(["project", "restore", "--archive", str(archive)]) == 2
        restored = tmp_path / "cli-restored-checkpoint"
        portable.snapshot(destination, UUID(project), restored)
        assert portable.verify_bundle(restored).table_counts == bundle.table_counts
        clock = next(row for name, row in portable.rows(restored) if name == "action_logs")
        assert int(clock["clock_offset_ns"]) == 123456789012345


def test_stage10_configured_limits_preserve_published_research(storage):
    from dataclasses import replace

    repository, settings, _ = storage
    with TestClient(create_app(settings)) as client:
        project, capture, stream, version, first, _, _, observation = stage9_research(client)
        previous = client.get(f"/api/v1/validation-runs/{first}").json()
        evidence = client.get(f"/api/v1/streams/{stream}/bytes?offset=0&length=2").json()
        corpus = previous["snapshot"]["corpus"]["id"]
        framed = client.get(f"/api/v1/streams/{stream}/framing").json()["items"][0]["id"]
    limited = replace(settings, max_validation_results=1, max_interpretation_bytes=1)
    with TestClient(create_app(limited)) as client:
        before = client.get(f"/api/v1/projects/{project}/validation-runs").json()
        request = client.post(
            f"/api/v1/projects/{project}/validation-runs",
            json={
                "corpus_version_id": corpus,
                "interpretation_version_id": version["id"],
            },
        )
        failed = finish(client, request.json()["id"])
        assert failed["status"] == "failed" and failed["result"] is None
        assert "rows 2/1" in failed["error"]
        assert client.get(f"/api/v1/projects/{project}/validation-runs").json() == before
        request = client.post(
            f"/api/v1/framing-runs/{framed}/interpretations", json={"version_id": version["id"]}
        )
        failed = finish(client, request.json()["id"])
        assert failed["status"] == "failed" and failed["result"] is None
        assert "bytes" in failed["error"]
        assert client.get(f"/api/v1/validation-runs/{first}").json() == previous
        assert client.get(f"/api/v1/streams/{stream}/bytes?offset=0&length=2").json() == evidence
        assert (
            client.get(f"/api/v1/projects/{project}/observations").json()["items"][0] == observation
        )
    with TestClient(create_app(replace(settings, max_packets=1))) as client:
        before = client.get(f"/api/v1/projects/{project}/captures").json()
        failed = finish(client, upload(client, project, "tcp/reused-tuple.pcap"))
        assert failed["status"] == "failed" and "max_packets" in failed["error"]
        assert client.get(f"/api/v1/projects/{project}/captures").json() == before
    assert not list(repository.safe_path(UUID(project), ".staging").iterdir())


def test_stage10_real_processing_cancellation_and_concurrent_reads(storage, tmp_path):
    """Cancel after genuine worker progress, with old bytes readable on the same API."""

    import dpkt

    repository, settings, _ = storage
    capture_path = tmp_path / "long.pcap"
    # Many one-byte messages create a sustained framing/validation workload.
    with capture_path.open("wb") as file:
        writer = dpkt.pcap.Writer(file)
        for i in range(100):
            tcp = dpkt.tcp.TCP(
                sport=41000, dport=9000, seq=100 + i * 1400, flags=16, data=b"x" * 1400
            )
            ip = dpkt.ip.IP(src=b"\xc0\x00\x02\x01", dst=b"\xc0\x00\x02\x02", p=6, ttl=64, data=tcp)
            ip.len = len(ip)
            frame = bytes(
                dpkt.ethernet.Ethernet(
                    src=b"\x02\0\0\0\0\x01", dst=b"\x02\0\0\0\0\x02", type=0x0800, data=ip
                )
            )
            writer.writepkt(frame, ts=1700000000 + i / 1000)
    with TestClient(create_app(settings)) as client:
        project, old_capture, old_stream, _, first, _, _, _ = stage9_research(client)
        stable = client.get(f"/api/v1/streams/{old_stream}/bytes?offset=0&length=2").json()
        uploaded = client.post(
            f"/api/v1/projects/{project}/captures",
            files={"file": ("long.pcap", capture_path.read_bytes())},
        )
        capture = finish(client, uploaded.json()["id"])["result"]["capture_id"]
        assert finish(client, reconstruct_job(client, capture))["status"] == "succeeded"
        stream = client.get(f"/api/v1/captures/{capture}/sessions").json()["items"][0]["streams"][
            0
        ]["id"]
        spec = {"rule": {"kind": "fixed", "size": 1}}
        model = client.post(
            f"/api/v1/projects/{project}/interpretations",
            json={
                "document_json": json.dumps(
                    {
                        "schema_version": "interpretation-1",
                        "name": "Bytes",
                        "framing": spec,
                        "fields": [{"kind": "bytes", "name": "raw", "length": 1}],
                    }
                ),
            },
        ).json()
        corpus = client.post(
            f"/api/v1/projects/{project}/corpora",
            json={
                "name": "Cancellation",
                "spec": {"capture_ids": [capture]},
            },
        ).json()
        requests = [
            (f"/api/v1/streams/{stream}/framing", spec),
            (
                f"/api/v1/projects/{project}/validation-runs",
                {
                    "corpus_version_id": corpus["id"],
                    "interpretation_version_id": model["id"],
                },
            ),
        ]
        latencies = []
        for path, body in requests:
            job_id = client.post(path, json=body).json()["id"]
            deadline = time.monotonic() + 15
            while True:
                state = client.get(f"/api/v1/jobs/{job_id}").json()
                if state["status"] == "running" and state["completed"] >= 65536:
                    break
                assert state["status"] not in {"committing", "succeeded", "failed"}, state
                assert time.monotonic() < deadline
                time.sleep(0.005)
            start = time.monotonic()
            assert (
                client.get(f"/api/v1/streams/{old_stream}/bytes?offset=0&length=2").json() == stable
            )
            assert client.get(f"/api/v1/captures/{old_capture}/packets?limit=1").status_code == 200
            assert client.get(f"/api/v1/validation-runs/{first}").status_code == 200
            latencies.append(time.monotonic() - start)
            assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelling"
            state = finish(client, job_id)
            assert state["status"] == "cancelled" and state["result"] is None
        assert client.get(f"/api/v1/streams/{stream}/framing").json()["items"] == []
        assert len(client.get(f"/api/v1/projects/{project}/validation-runs").json()["items"]) == 2
        assert client.get(f"/api/v1/streams/{old_stream}/bytes?offset=0&length=2").json() == stable
        # Also cancel field decoding after a batch of real messages has been processed.
        parse_spec = {"rule": {"kind": "fixed", "size": 4}}
        framed_job = client.post(f"/api/v1/streams/{stream}/framing", json=parse_spec).json()
        framed = finish(client, framed_job["id"])
        assert framed["status"] == "succeeded", framed
        framing_id = framed["result"]["run_id"]
        parse_model = client.post(
            f"/api/v1/projects/{project}/interpretations",
            json={
                "document_json": json.dumps(
                    {
                        "schema_version": "interpretation-1",
                        "name": "Four bytes",
                        "framing": parse_spec,
                        "fields": [{"kind": "bytes", "name": "raw", "length": 4}],
                    }
                )
            },
        ).json()
        job_id = client.post(
            f"/api/v1/framing-runs/{framing_id}/interpretations",
            json={"version_id": parse_model["id"]},
        ).json()["id"]
        deadline = time.monotonic() + 15
        while True:
            state = client.get(f"/api/v1/jobs/{job_id}").json()
            if state["status"] == "running" and state["completed"] > 0:
                break
            assert state["status"] not in {"committing", "succeeded", "failed"}, state
            assert time.monotonic() < deadline
            time.sleep(0.005)
        start = time.monotonic()
        assert client.get(f"/api/v1/streams/{old_stream}/bytes?offset=0&length=2").json() == stable
        latencies.append(time.monotonic() - start)
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelling"
        state = finish(client, job_id)
        assert state["status"] == "cancelled" and state["result"] is None
        assert (
            client.get(f"/api/v1/framing-runs/{framing_id}/interpretations").json()["items"] == []
        )
        assert max(latencies) < 3, latencies
        print("Concurrent existing bytes/packets/run reads, seconds:", latencies)
    assert not list(repository.safe_path(UUID(project), ".staging").iterdir())
