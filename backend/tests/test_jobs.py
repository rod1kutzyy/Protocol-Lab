import time

from fastapi.testclient import TestClient

from protocol_lab.api.app import create_app
from protocol_lab.services.settings import Settings


def terminal(client, job_id):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        data = client.get(f"/api/v1/jobs/{job_id}").json()
        if data["status"] in {"succeeded", "cancelled", "failed"}:
            return data
        time.sleep(0.02)
    raise AssertionError("worker did not finish")


def test_process_progress_and_sse():
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/jobs/diagnostic", json={"steps": 3, "delay_ms": 5})
        assert response.status_code == 202
        job_id = response.json()["id"]
        data = terminal(client, job_id)
        assert data["status"] == "succeeded"
        assert data["completed"] == 3
        assert data["result"] == {"checked_steps": 3}
        events = client.get(f"/api/v1/jobs/{job_id}/events")
        assert events.headers["content-type"].startswith("text/event-stream")
        assert "event: job" in events.text
        assert '"status":"succeeded"' in events.text
        # Reconnecting to a completed job also delivers the terminal snapshot.
        assert (
            client.get(f"/api/v1/jobs/{job_id}/events", headers={"Last-Event-ID": "999"}).text
            == events.text
        )


def test_running_cancellation_does_not_publish_result():
    with TestClient(create_app()) as client:
        job_id = client.post(
            "/api/v1/jobs/diagnostic", json={"steps": 100, "delay_ms": 100}
        ).json()["id"]
        deadline = time.monotonic() + 5
        while client.get(f"/api/v1/jobs/{job_id}").json()["completed"] == 0:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert client.get("/api/v1/health").status_code == 200
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelling"
        data = terminal(client, job_id)
        assert data["status"] == "cancelled"
        assert data["result"] is None
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json() == data


def test_queued_cancellation_and_limits():
    with TestClient(create_app()) as client:
        client.app.state.jobs.max_workers = 0
        client.app.state.jobs.max_jobs = 1
        job_id = client.post("/api/v1/jobs/diagnostic", json={}).json()["id"]
        assert client.post("/api/v1/jobs/diagnostic", json={}).status_code == 429
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "cancelled"
        assert client.get("/api/v1/jobs").json()["items"][0]["result"] is None


def test_failure_is_terminal():
    with TestClient(create_app()) as client:
        job_id = client.post(
            "/api/v1/jobs/diagnostic", json={"steps": 100, "delay_ms": 100}
        ).json()["id"]
        deadline = time.monotonic() + 5
        while client.get(f"/api/v1/jobs/{job_id}").json()["completed"] == 0:
            assert time.monotonic() < deadline
            time.sleep(0.02)
        from uuid import UUID

        client.app.state.jobs.jobs[UUID(job_id)].process.terminate()
        data = terminal(client, job_id)
        assert data["status"] == "failed"
        assert data["error"]
        assert data["result"] is None


def test_invalid_requests_and_missing_jobs():
    with TestClient(create_app(Settings())) as client:
        for body in [{"steps": 0}, {"steps": 101}, {"delay_ms": 301}, {"kind": "arbitrary"}]:
            assert client.post("/api/v1/jobs/diagnostic", json=body).status_code == 422
        assert (
            client.get("/api/v1/jobs/00000000-0000-0000-0000-000000000000/events").status_code
            == 404
        )
        assert client.get("/api/v1/health").json()["persistence"] == "not_configured"


def prepared_worker(send, cancel):
    send.send(("prepared", {"packet_count": 0, "diagnostics": {}}))
    send.close()


def test_publication_closes_cancellation_and_allows_other_requests():
    import threading

    from protocol_lab.services.jobs import JobManager

    started = threading.Event()
    release = threading.Event()

    def finalize(_summary):
        started.set()
        assert release.wait(15)
        return {"outcome": "imported", "capture_id": "test"}

    cleaned = []
    with TestClient(create_app()) as client:
        manager: JobManager = client.app.state.jobs
        job_id = client.portal.call(
            manager.create_import, prepared_worker, (), 0, finalize, lambda: cleaned.append(True)
        ).id
        assert started.wait(5)
        assert client.get(f"/api/v1/jobs/{job_id}").json()["status"] == "committing"
        assert client.post(f"/api/v1/jobs/{job_id}/cancel").json()["status"] == "committing"
        assert client.get("/api/v1/health").status_code == 200
        # Adding a job during an awaited DB publication must not kill the scheduler.
        next_job = client.post("/api/v1/jobs/diagnostic", json={"steps": 1, "delay_ms": 0}).json()[
            "id"
        ]
        try:
            assert terminal(client, next_job)["status"] == "succeeded"
        finally:
            release.set()
        assert terminal(client, job_id)["status"] == "succeeded"
        assert terminal(client, next_job)["status"] == "succeeded"
    assert cleaned


def test_project_routes_report_missing_database():
    from protocol_lab.services.settings import Settings

    with TestClient(create_app(Settings())) as client:
        response = client.post("/api/v1/projects", json={"name": "Research"})
        assert response.status_code == 503
        assert "PostgreSQL" in response.json()["detail"]
        assert client.get("/api/v1/health").status_code == 200


def test_upload_limit_before_multipart_spooling():
    from protocol_lab.services.settings import Settings

    path = "/api/v1/projects/00000000-0000-0000-0000-000000000000/captures"
    with TestClient(create_app(Settings(max_upload_bytes=20))) as client:
        response = client.post(path, content=b"x" * (1024 * 1024 + 21))
        assert response.status_code == 413
        boundary = b'--test\r\nContent-Disposition: form-data; name="file"; filename="data"\r\n\r\n'
        chunks = iter([boundary, b"x" * (1024 * 1024 + 21), b"\r\n--test--\r\n"])
        response = client.post(
            path, content=chunks, headers={"content-type": "multipart/form-data; boundary=test"}
        )
        assert response.status_code == 413


def test_interpretation_schema_check_available_without_database():
    from protocol_lab.services.settings import Settings

    with TestClient(create_app(Settings())) as client:
        response = client.get("/api/v1/interpretations/schema")
        assert response.status_code == 200 and response.json()["$defs"]["IntField"]
        assert (
            client.post(
                "/api/v1/interpretations/check", json={"document_json": '{"name":1,"name":2}'}
            ).json()["valid"]
            is False
        )
        assert (
            client.post(
                "/api/v1/interpretations/check", json={"document_json": '{"name":NaN}'}
            ).json()["valid"]
            is False
        )
        assert client.post("/api/v1/interpretations/check", json={"document_json": "{}"}).json()[
            "issues"
        ]


def test_configured_worker_and_registry_limits():
    with TestClient(create_app(Settings(max_workers=1, max_jobs=1))) as client:
        assert client.app.state.jobs.max_workers == 1
        assert client.app.state.jobs.max_jobs == 1
        job = client.post("/api/v1/jobs/diagnostic", json={"steps": 2, "delay_ms": 100}).json()
        assert client.post("/api/v1/jobs/diagnostic", json={}).status_code == 429
        assert terminal(client, job["id"])["status"] == "succeeded"
