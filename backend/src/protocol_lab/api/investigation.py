import asyncio
import functools
import hashlib
import shutil
from ipaddress import IPv4Address
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import Field

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.api.tcp import LimitBytes, SessionList
from protocol_lab.domain.models import Record
from protocol_lab.research.action_logs import MAX_LOG_BYTES, ActionEvent, LogMapping, log_rows
from protocol_lab.services.investigation import log_worker, search_worker
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.storage.reconstruction import ObservationInput, ReconstructionStore
from protocol_lab.storage.research import (
    ActionLink,
    ClockUpdate,
    CorrelatedActions,
    ResearchStore,
    StoredLog,
)

router = APIRouter(prefix="/api/v1")
NanoTime = Annotated[str, Query(pattern=r"^-?\d{1,30}$")]


class LogList(Record):
    items: list[StoredLog]
    next_offset: int | None


class ActionList(Record):
    items: list[ActionEvent]
    next_offset: int | None


class LinkList(Record):
    items: list[ActionLink]
    next_offset: int | None


class LogPreview(Record):
    fields: list[str]
    row_count: int
    sample: list[dict]


class PacketBytes(Record):
    packet_id: UUID
    offset: int
    length: int
    data_hex: str


class SearchInput(Record):
    pattern_hex: str = Field(min_length=2, max_length=512, pattern=r"^[a-fA-F0-9]+$")
    start: int = Field(default=0, ge=0)


@router.get("/projects/{project_id}/sessions", response_model=SessionList)
async def sessions(
    project_id: UUID,
    request: Request,
    offset: Offset = 0,
    limit: Limit = 100,
    capture_id: UUID | None = None,
    address: IPv4Address | None = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    start_ns: NanoTime | None = None,
    end_ns: NanoTime | None = None,
):
    items = await call(
        ReconstructionStore(store(request)).project_sessions,
        project_id,
        offset,
        limit + 1,
        capture_id,
        str(address) if address else None,
        port,
        start_ns,
        end_ns,
    )
    return SessionList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/packets/{packet_id}/bytes", response_model=PacketBytes)
async def packet_bytes(
    packet_id: UUID, request: Request, offset: Offset, length: Annotated[int, Query(ge=1, le=4096)]
):
    return await call(store(request).packet_bytes, packet_id, offset, length)


@router.post("/streams/{stream_id}/search", response_model=JobSnapshot, status_code=202)
async def search(stream_id: UUID, body: SearchInput, request: Request):
    stream = await call(ReconstructionStore(store(request)).stream, stream_id)
    if len(body.pattern_hex) % 2 or body.start > stream.extent:
        raise HTTPException(422, "Search pattern needs complete hex bytes and start within extent")
    try:
        return request.app.state.jobs.create_import(
            search_worker,
            (
                request.app.state.settings.database_url,
                str(store(request).root),
                stream_id,
                body.pattern_hex.lower(),
                body.start,
            ),
            stream.extent,
            lambda summary: summary,
            lambda: None,
            kind="stream_search",
        )
    except JobLimitError as exc:
        raise HTTPException(429, str(exc)) from None


async def log_data(file):
    try:
        data = await file.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise HTTPException(413, "Action log exceeds 16 MiB")
        return data
    finally:
        await file.close()


@router.post("/projects/{project_id}/action-logs/preview", response_model=LogPreview)
async def preview(
    project_id: UUID,
    request: Request,
    file: Annotated[UploadFile, File()],
    format: Annotated[Literal["csv", "json"], Form()],
    delimiter: Annotated[Literal[",", ";", "\t"], Form()] = ",",
):
    await call(store(request).get, project_id)
    data = await log_data(file)
    fields, rows = await call(log_rows, data, format, delimiter)
    return LogPreview(fields=fields, row_count=len(rows), sample=rows[:5])


@router.post("/projects/{project_id}/action-logs", response_model=JobSnapshot, status_code=202)
async def import_log(
    project_id: UUID,
    request: Request,
    file: Annotated[UploadFile, File()],
    format: Annotated[Literal["csv", "json"], Form()],
    mapping_json: Annotated[str, Form()],
):
    projects = store(request)
    await call(projects.get, project_id)
    try:
        mapping = LogMapping.model_validate_json(mapping_json)
    except ValueError:
        await file.close()
        raise HTTPException(422, "Invalid action-log field mapping") from None
    data = await log_data(file)
    stage = projects.safe_path(project_id, f".staging/{uuid4()}")
    stage.mkdir()
    source, events = stage / "source", stage / "events.jsonl"
    log_id = uuid4()
    try:
        await asyncio.to_thread(source.write_bytes, data)
        checksum = hashlib.sha256(data).hexdigest()
        finalize = functools.partial(
            ResearchStore(projects).publish_log,
            project_id,
            log_id,
            source,
            events,
            checksum,
            format,
            mapping,
        )
        return request.app.state.jobs.create_import(
            log_worker,
            (str(source), str(events), log_id, format, mapping),
            len(data),
            finalize,
            functools.partial(shutil.rmtree, stage, ignore_errors=True),
            kind="action_log_import",
        )
    except JobLimitError as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


@router.get("/projects/{project_id}/action-logs", response_model=LogList)
async def logs(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(ResearchStore(store(request)).logs, project_id, offset, limit + 1)
    return LogList(items=items[:limit], next_offset=offset + limit if len(items) > limit else None)


@router.patch("/action-logs/{log_id}/clock", response_model=StoredLog)
async def clock(log_id: UUID, body: ClockUpdate, request: Request):
    return await call(ResearchStore(store(request)).clock, log_id, body)


@router.get("/projects/{project_id}/actions", response_model=ActionList)
async def actions(
    project_id: UUID,
    request: Request,
    offset: Offset = 0,
    limit: Limit = 100,
    log_id: UUID | None = None,
):
    items = await call(ResearchStore(store(request)).actions, project_id, offset, limit + 1, log_id)
    return ActionList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/streams/{stream_id}/actions", response_model=CorrelatedActions)
async def correlations(
    stream_id: UUID,
    request: Request,
    offset: Offset,
    length: LimitBytes,
    page: Offset = 0,
    limit: Limit = 100,
    window_ns: Annotated[int, Query(ge=0, le=60 * 10**9)] = 0,
):
    return await call(
        ResearchStore(store(request)).correlate, stream_id, offset, length, window_ns, page, limit
    )


@router.post(
    "/projects/{project_id}/actions/{action_id}/links", response_model=ActionLink, status_code=201
)
async def link(project_id: UUID, action_id: UUID, body: ObservationInput, request: Request):
    return await call(ResearchStore(store(request)).link, project_id, action_id, body)


@router.get("/projects/{project_id}/action-links", response_model=LinkList)
async def links(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(ResearchStore(store(request)).links, project_id, offset, limit + 1)
    return LinkList(items=items[:limit], next_offset=offset + limit if len(items) > limit else None)
