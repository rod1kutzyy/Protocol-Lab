import asyncio
from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from protocol_lab import __version__
from protocol_lab.api.framing import router as framing_router
from protocol_lab.api.inference import router as inference_router
from protocol_lab.api.interpretations import router as interpretations_router
from protocol_lab.api.investigation import router as investigation_router
from protocol_lab.api.limits import UploadLimitMiddleware
from protocol_lab.api.portability import router as portability_router
from protocol_lab.api.projects import router
from protocol_lab.api.tcp import router as tcp_router
from protocol_lab.api.validation import router as validation_router
from protocol_lab.services.jobs import (
    TERMINAL,
    DiagnosticRequest,
    JobLimitError,
    JobManager,
    JobSnapshot,
)
from protocol_lab.services.settings import Settings
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.projects import ProjectStore


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = __version__
    persistence: str = "not_configured"


class JobListResponse(BaseModel):
    items: list[JobSnapshot]


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.environment()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = make_engine(config.database_url) if config.database_url else None
        app.state.settings = config
        app.state.store = ProjectStore(engine, config.project_root) if engine else None
        manager = JobManager(max_workers=config.max_workers, max_jobs=config.max_jobs)
        app.state.jobs = manager
        await manager.start()
        try:
            yield
        finally:
            await manager.close()
            if engine:
                engine.dispose()

    app = FastAPI(title="Protocol Lab", version=__version__, lifespan=lifespan)

    app.add_middleware(
        UploadLimitMiddleware,
        max_bytes=config.max_upload_bytes + 1024 * 1024,
        max_archive_bytes=config.max_archive_bytes + 1024 * 1024,
    )
    app.include_router(portability_router)
    app.include_router(router)
    app.include_router(tcp_router)
    app.include_router(investigation_router)
    app.include_router(framing_router)
    app.include_router(interpretations_router)
    app.include_router(validation_router)
    app.include_router(inference_router)

    def manager(request: Request) -> JobManager:
        return request.app.state.jobs

    def find(request: Request, job_id: UUID) -> JobSnapshot:
        try:
            return manager(request).get(job_id)
        except KeyError:
            raise HTTPException(
                404, "Job not found; the development registry resets on restart"
            ) from None

    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(
            persistence="postgresql_configured" if config.database_url else "not_configured"
        )

    @app.post("/api/v1/jobs/diagnostic", response_model=JobSnapshot, status_code=202)
    async def start_job(body: DiagnosticRequest, request: Request):
        try:
            return manager(request).create(body)
        except JobLimitError as exc:
            raise HTTPException(429, str(exc)) from None

    @app.get("/api/v1/jobs", response_model=JobListResponse)
    async def list_jobs(request: Request):
        return JobListResponse(items=[job.snapshot for job in manager(request).jobs.values()])

    @app.get("/api/v1/jobs/{job_id}", response_model=JobSnapshot)
    async def get_job(job_id: UUID, request: Request):
        return find(request, job_id)

    @app.post("/api/v1/jobs/{job_id}/cancel", response_model=JobSnapshot)
    async def cancel_job(job_id: UUID, request: Request):
        find(request, job_id)
        return manager(request).cancel(job_id)

    @app.get(
        "/api/v1/jobs/{job_id}/events",
        response_class=StreamingResponse,
        responses={200: {"content": {"text/event-stream": {}}}},
    )
    async def job_events(job_id: UUID, request: Request):
        find(request, job_id)

        async def events():
            # Reconnect always receives a full current snapshot, including a terminal state.
            revision = -1
            heartbeat = 0
            while not await request.is_disconnected():
                snapshot = find(request, job_id)
                if snapshot.revision != revision:
                    revision = snapshot.revision
                    yield f"id: {revision}\nevent: job\ndata: {snapshot.model_dump_json()}\n\n"
                    if snapshot.status in TERMINAL:
                        return
                elif heartbeat >= 100:
                    yield ": heartbeat\n\n"
                    heartbeat = 0
                heartbeat += 1
                await asyncio.sleep(0.1)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


app = create_app()
