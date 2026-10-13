import functools
import shutil
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.domain.models import Observation, Record
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.services.reconstruction import reconstruction_worker
from protocol_lab.storage.reconstruction import (
    ObservationInput,
    ReconstructionStore,
    SessionView,
    StreamBytes,
)
from protocol_lab.tcp.reassembly import RebuiltStream, ReconstructionSettings

LimitBytes = Annotated[int, Query(ge=1, le=65536)]

router = APIRouter(prefix="/api/v1")


class SessionList(Record):
    items: list[SessionView]
    next_offset: int | None


class ObservationList(Record):
    items: list[Observation]
    next_offset: int | None


@router.post("/captures/{capture_id}/reconstruct", response_model=JobSnapshot, status_code=202)
async def start_reconstruction(capture_id: UUID, body: ReconstructionSettings, request: Request):
    projects = store(request)
    capture = await call(projects.get_capture, capture_id)
    await call(projects.get, capture.project_id)
    stage = projects.safe_path(capture.project_id, f".staging/{uuid4()}")
    stage.mkdir()
    artifact = stage / "reconstruction.json"
    repository = ReconstructionStore(projects)
    try:
        return request.app.state.jobs.create_import(
            reconstruction_worker,
            (
                request.app.state.settings.database_url,
                str(projects.root),
                capture_id,
                str(artifact),
                body,
            ),
            capture.packet_count,
            functools.partial(repository.publish, capture_id, artifact),
            functools.partial(shutil.rmtree, stage, ignore_errors=True),
            kind="tcp_reconstruction",
        )
    except JobLimitError as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


@router.get("/captures/{capture_id}/sessions", response_model=SessionList)
async def sessions(capture_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(ReconstructionStore(store(request)).sessions, capture_id, offset, limit + 1)
    return SessionList(
        items=items[:limit],
        next_offset=offset + limit if len(items) > limit else None,
    )


@router.get("/sessions/{session_id}", response_model=SessionView)
async def session(session_id: UUID, request: Request):
    return await call(ReconstructionStore(store(request)).view, session_id)


@router.get("/streams/{stream_id}", response_model=RebuiltStream)
async def stream(stream_id: UUID, request: Request):
    return await call(ReconstructionStore(store(request)).stream, stream_id)


@router.get("/streams/{stream_id}/bytes", response_model=StreamBytes)
async def stream_bytes(stream_id: UUID, request: Request, offset: Offset, length: LimitBytes):
    return await call(ReconstructionStore(store(request)).ranges, stream_id, offset, length)


@router.post("/projects/{project_id}/observations", response_model=Observation, status_code=201)
async def observe(project_id: UUID, body: ObservationInput, request: Request):
    return await call(ReconstructionStore(store(request)).observe, project_id, body)


@router.get("/projects/{project_id}/observations", response_model=ObservationList)
async def observations(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(
        ReconstructionStore(store(request)).observations, project_id, offset, limit + 1
    )
    return ObservationList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )
