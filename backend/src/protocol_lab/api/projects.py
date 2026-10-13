import asyncio
import functools
import hashlib
import os
import shutil
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from protocol_lab.capture.index import CaptureError, IndexedPacket, IndexSettings, capture_format
from protocol_lab.services.imports import import_worker
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.storage.projects import Project, ProjectStore, StorageError, StoredCapture

router = APIRouter(prefix="/api/v1")
Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


class CreateProject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)


class ProjectList(BaseModel):
    items: list[Project]
    next_offset: int | None


class CaptureList(BaseModel):
    items: list[StoredCapture]
    next_offset: int | None


class PacketList(BaseModel):
    items: list[IndexedPacket]
    next_offset: int | None


class VerifyResult(BaseModel):
    capture_id: UUID
    sha256: str
    status: Literal["verified"]


def store(request: Request) -> ProjectStore:
    value = request.app.state.store
    if value is None:
        raise HTTPException(
            503, "PostgreSQL is not configured; set PROTOCOL_LAB_DATABASE_URL and apply migrations"
        )
    return value


async def call(function, *args):
    try:
        return await asyncio.to_thread(function, *args)
    except KeyError:
        raise HTTPException(
            404, "Requested project, capture, session, stream or packet not found"
        ) from None
    except StorageError as exc:
        raise HTTPException(409, str(exc)) from None
    except (CaptureError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None
    except SQLAlchemyError:
        raise HTTPException(
            503, "PostgreSQL unavailable or migrations not applied; sources were not modified"
        ) from None


@router.post("/projects", response_model=Project, status_code=201)
async def create_project(body: CreateProject, request: Request):
    return await call(store(request).create, body.name)


@router.get("/projects", response_model=ProjectList)
async def list_projects(request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(store(request).list_projects, offset, limit + 1)
    return ProjectList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/projects/{project_id}", response_model=Project)
async def get_project(project_id: UUID, request: Request):
    return await call(store(request).get, project_id)


@router.get("/projects/{project_id}/captures", response_model=CaptureList)
async def list_captures(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(store(request).captures, project_id, offset, limit + 1)
    return CaptureList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.post("/projects/{project_id}/captures", response_model=JobSnapshot, status_code=202)
async def import_capture(
    project_id: UUID,
    request: Request,
    file: Annotated[UploadFile, File()],
    checksum_policy: Annotated[Literal["warn", "ignore", "reject"], Form()] = "warn",
):
    repository = store(request)
    await call(repository.get, project_id)
    manager = request.app.state.jobs
    if len(manager.jobs) >= manager.max_jobs:
        raise HTTPException(429, "Job registry limit reached")
    stage = repository.safe_path(project_id, f".staging/{uuid4()}")
    stage.mkdir()
    source = stage / "source"
    index = stage / "packets.jsonl"
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("xb") as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > request.app.state.settings.max_upload_bytes:
                    raise HTTPException(
                        413, "Capture exceeds max_upload_bytes; no capture published"
                    )
                digest.update(chunk)
                await asyncio.to_thread(output.write, chunk)
            output.flush()
            await asyncio.to_thread(os.fsync, output.fileno())
        file_format = await call(capture_format, source)
        capture_id = uuid4()
        config = request.app.state.settings
        settings = IndexSettings(
            checksum_policy=checksum_policy,
            max_block_bytes=config.max_block_bytes,
            max_packets=config.max_packets,
        )
        finalize = functools.partial(
            repository.finalize_import,
            project_id,
            capture_id,
            source,
            index,
            digest.hexdigest(),
            file_format,
            settings,
        )
        cleanup = functools.partial(shutil.rmtree, stage, ignore_errors=True)
        return manager.create_import(
            import_worker, (str(source), str(index), capture_id, settings), size, finalize, cleanup
        )
    except JobLimitError as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        await file.close()


@router.get("/captures/{capture_id}", response_model=StoredCapture)
async def get_capture(capture_id: UUID, request: Request):
    return await call(store(request).get_capture, capture_id)


@router.get("/captures/{capture_id}/packets", response_model=PacketList)
async def get_packets(capture_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(store(request).packets, capture_id, offset, limit + 1)
    return PacketList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.post("/captures/{capture_id}/verify", response_model=VerifyResult)
async def verify_source(capture_id: UUID, request: Request):
    return await call(store(request).verify_source, capture_id)


@router.get("/packets/{packet_id}", response_model=IndexedPacket)
async def get_packet(packet_id: UUID, request: Request):
    return await call(store(request).packet, packet_id)
