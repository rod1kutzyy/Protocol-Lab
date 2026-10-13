import functools
import shutil
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field, ValidationError

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.domain.models import Record
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.engine import MessageResult
from protocol_lab.interpretation.schema import json_schema
from protocol_lab.services.interpretations import interpretation_worker
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.storage.interpretations import (
    DecodeRun,
    InterpretationStore,
    MessageSummary,
    StoredInterpretation,
)

router = APIRouter(prefix="/api/v1")


class ModelText(Record):
    document_json: str = Field(max_length=131072)


class SaveModel(ModelText):
    parent_id: UUID | None = None


class ModelIssue(Record):
    path: str
    message: str


class ModelCheck(Record):
    valid: bool
    issues: list[ModelIssue]


class VersionList(Record):
    items: list[StoredInterpretation]
    next_offset: int | None


class DecodeRequest(Record):
    version_id: UUID


class DecodeRunList(Record):
    items: list[DecodeRun]
    next_offset: int | None


class DecodeResultList(Record):
    items: list[MessageSummary]
    next_offset: int | None


@router.get("/interpretations/schema")
async def schema() -> dict[str, Any]:
    return json_schema()


@router.post("/interpretations/check", response_model=ModelCheck)
async def check(body: ModelText):
    try:
        load_model(body.document_json)
        return ModelCheck(valid=True, issues=[])
    except ValidationError as exc:
        return ModelCheck(
            valid=False,
            issues=[
                ModelIssue(path=".".join(map(str, e["loc"])), message=e["msg"])
                for e in exc.errors(include_input=False, include_context=False)
            ],
        )
    except (ValueError, RecursionError):
        return ModelCheck(
            valid=False,
            issues=[
                ModelIssue(
                    path="", message="Invalid JSON, duplicate properties or excessive nesting"
                )
            ],
        )


@router.post(
    "/projects/{project_id}/interpretations", response_model=StoredInterpretation, status_code=201
)
async def save(project_id: UUID, body: SaveModel, request: Request):
    try:
        model = load_model(body.document_json)
    except (ValueError, RecursionError):
        raise HTTPException(
            422, "Invalid interpretation; use /interpretations/check for field diagnostics"
        ) from None
    return await call(InterpretationStore(store(request)).save, project_id, model, body.parent_id)


@router.get("/projects/{project_id}/interpretations", response_model=VersionList)
async def versions(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(InterpretationStore(store(request)).versions, project_id, offset, limit + 1)
    return VersionList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/interpretation-versions/{version_id}", response_model=StoredInterpretation)
async def version(version_id: UUID, request: Request):
    return await call(InterpretationStore(store(request)).version, version_id)


@router.post(
    "/framing-runs/{framing_id}/interpretations", response_model=JobSnapshot, status_code=202
)
async def decode(framing_id: UUID, body: DecodeRequest, request: Request):
    projects = store(request)
    repository = InterpretationStore(projects)
    _, stream, capture, _, _ = await call(repository.context, framing_id, body.version_id)
    stage = projects.safe_path(capture.project_id, f".staging/{uuid4()}")
    stage.mkdir()
    artifact = stage / "interpretation.jsonl"
    cleanup = functools.partial(shutil.rmtree, stage, ignore_errors=True)
    try:
        return request.app.state.jobs.create_import(
            interpretation_worker,
            (
                request.app.state.settings.database_url,
                str(projects.root),
                framing_id,
                body.version_id,
                str(artifact),
                request.app.state.settings.max_interpretation_bytes,
            ),
            stream.extent,
            functools.partial(repository.publish, framing_id, body.version_id, artifact),
            cleanup,
            kind="message_interpretation",
        )
    except JobLimitError as exc:
        cleanup()
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        cleanup()
        raise


@router.get("/framing-runs/{framing_id}/interpretations", response_model=DecodeRunList)
async def runs(framing_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(InterpretationStore(store(request)).runs, framing_id, offset, limit + 1)
    return DecodeRunList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/interpretation-runs/{run_id}", response_model=DecodeRun)
async def run(run_id: UUID, request: Request):
    return await call(InterpretationStore(store(request)).get, run_id)


@router.get("/interpretation-runs/{run_id}/results", response_model=DecodeResultList)
async def results(run_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(InterpretationStore(store(request)).results, run_id, offset, limit + 1)
    return DecodeResultList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/interpretation-runs/{run_id}/results/{piece_id}", response_model=MessageResult)
async def result(run_id: UUID, piece_id: UUID, request: Request):
    return await call(InterpretationStore(store(request)).result, run_id, piece_id)
