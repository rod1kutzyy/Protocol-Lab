import functools
import shutil
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.domain.models import Record
from protocol_lab.framing.engine import FramingSpec, Piece
from protocol_lab.services.framing import framing_worker
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.storage.framing import FramingStore, RunView

router = APIRouter(prefix="/api/v1")


class RunList(Record):
    items: list[RunView]
    next_offset: int | None


class PieceList(Record):
    items: list[Piece]
    next_offset: int | None


@router.post("/streams/{stream_id}/framing", response_model=JobSnapshot, status_code=202)
async def start_framing(stream_id: UUID, body: FramingSpec, request: Request):
    projects = store(request)
    repository = FramingStore(projects)
    stream, capture = await call(repository.context, stream_id)
    if body.start > stream.extent or (
        body.rule.kind == "manual" and any(r.end > stream.extent for r in body.rule.ranges)
    ):
        raise HTTPException(422, "Framing start/manual range exceeds stream extent")
    stage = projects.safe_path(capture.project_id, f".staging/{uuid4()}")
    stage.mkdir()
    artifact = stage / "framing.json"
    cleanup = functools.partial(shutil.rmtree, stage, ignore_errors=True)
    try:
        return request.app.state.jobs.create_import(
            framing_worker,
            (
                request.app.state.settings.database_url,
                str(projects.root),
                stream_id,
                body,
                str(artifact),
            ),
            stream.extent,
            functools.partial(repository.publish, stream_id, body, artifact),
            cleanup,
            kind="stream_framing",
        )
    except JobLimitError as exc:
        cleanup()
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        cleanup()
        raise


@router.get("/streams/{stream_id}/framing", response_model=RunList)
async def runs(stream_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(FramingStore(store(request)).runs, stream_id, offset, limit + 1)
    return RunList(items=items[:limit], next_offset=offset + limit if len(items) > limit else None)


@router.get("/framing-runs/{run_id}", response_model=RunView)
async def run(run_id: UUID, request: Request):
    return await call(FramingStore(store(request)).get, run_id)


@router.get("/framing-runs/{run_id}/pieces", response_model=PieceList)
async def pieces(run_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(FramingStore(store(request)).pieces, run_id, offset, limit + 1)
    return PieceList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )
