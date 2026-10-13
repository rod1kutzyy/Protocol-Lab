import asyncio
import functools
import os
import shutil
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response

from protocol_lab.api.projects import call, store
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.services.portability import portability_worker, publish_operation
from protocol_lab.storage.interpretations import InterpretationStore
from protocol_lab.storage.validation import ValidationStore

router = APIRouter(prefix="/api/v1")
Operation = Literal["save", "verify", "export", "report"]
Filename = Literal["project.zip", "report.md", "validation.json"]


def create_operation(
    request, repository, project_id, operation, stage, run_id=None, artifact_id=None
):
    artifact_id = artifact_id or uuid4()
    config = request.app.state.settings
    try:
        return request.app.state.jobs.create_import(
            portability_worker,
            (
                config.database_url,
                str(config.project_root),
                operation,
                project_id,
                str(stage),
                run_id,
            ),
            1,
            functools.partial(
                publish_operation, repository, project_id, operation, artifact_id, stage
            ),
            functools.partial(shutil.rmtree, stage, ignore_errors=True),
            kind="project_restore" if operation == "restore" else "project_operation",
        )
    except JobLimitError as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise HTTPException(429, str(exc)) from None


@router.post("/projects/restore", response_model=JobSnapshot, status_code=202)
async def restore_project(request: Request, file: Annotated[UploadFile, File()]):
    repository = store(request)
    # No user-provided path/filename is used for storage.
    stage = repository.root / ".transfers" / str(uuid4())
    if any(p.is_symlink() for p in (stage, stage.parent)):
        raise HTTPException(409, "Transfer directory must not be a symlink")
    stage.mkdir(parents=True)
    size = 0
    try:
        with (stage / "upload.zip").open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > request.app.state.settings.max_archive_bytes:
                    raise HTTPException(413, "Project archive exceeds configured upload limit")
                await asyncio.to_thread(output.write, chunk)
            output.flush()
            await asyncio.to_thread(os.fsync, output.fileno())
        return create_operation(request, repository, None, "restore", stage)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        await file.close()


@router.post(
    "/projects/{project_id}/operations/{operation}", response_model=JobSnapshot, status_code=202
)
async def project_operation(project_id: UUID, operation: Operation, request: Request):
    repository = store(request)
    await call(repository.get, project_id)
    artifact_id = uuid4()
    stage = repository.safe_path(project_id, f".staging/{artifact_id}")
    stage.mkdir()
    return create_operation(
        request, repository, project_id, operation, stage, artifact_id=artifact_id
    )


@router.get("/projects/{project_id}/exports/{artifact_id}/{filename}", response_class=FileResponse)
async def download(project_id: UUID, artifact_id: UUID, filename: Filename, request: Request):
    repository = store(request)
    await call(repository.get, project_id)
    path = repository.safe_path(project_id, f"exports/{artifact_id}/{filename}")
    if not path.is_file():
        raise HTTPException(
            404, "Completed export not found; rerun export after API restart if needed"
        )
    return FileResponse(
        path,
        filename=filename,
        media_type={
            "project.zip": "application/zip",
            "report.md": "text/markdown; charset=utf-8",
            "validation.json": "application/json",
        }[filename],
    )


@router.get(
    "/interpretation-versions/{version_id}/export",
    response_class=Response,
    responses={200: {"content": {"application/json": {}}}},
)
async def export_model(version_id: UUID, request: Request):
    version = await call(InterpretationStore(store(request)).version, version_id)
    return Response(
        version.document_json + "\n",
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="model-{version_id}.json"',
            "X-Model-SHA256": version.content_sha256,
        },
    )


@router.post("/validation-runs/{run_id}/export", response_model=JobSnapshot, status_code=202)
async def export_validation(run_id: UUID, request: Request):
    repository = store(request)
    run = await call(ValidationStore(repository).get, run_id)
    project_id = run.snapshot.project_id
    stage = repository.safe_path(project_id, f".staging/{uuid4()}")
    stage.mkdir()
    return create_operation(request, repository, project_id, "validation_json", stage, run_id)
