import functools
import shutil
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.domain.models import Observation, Record
from protocol_lab.research.hypotheses import HypothesisInput, StoredHypothesis
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.services.validation import validation_worker
from protocol_lab.storage.hypotheses import HypothesisStore
from protocol_lab.storage.validation import ValidationStore
from protocol_lab.validation.models import (
    Comparison,
    CorpusInput,
    Currentness,
    RunInput,
    Status,
    StoredCorpus,
    ValidationItem,
    ValidationRun,
    ValidationRunSummary,
    ValidationSummary,
)

router = APIRouter(prefix="/api/v1")


class HypothesisList(Record):
    items: list[StoredHypothesis]
    next_offset: int | None


class HypothesisEvidence(Record):
    items: list[Observation]


class CorpusList(Record):
    items: list[StoredCorpus]
    next_offset: int | None


class ValidationRunList(Record):
    items: list[ValidationRunSummary]
    next_offset: int | None


class ValidationResultList(Record):
    items: list[ValidationSummary]
    next_offset: int | None


@router.post("/projects/{project_id}/hypotheses", response_model=StoredHypothesis, status_code=201)
async def save_hypothesis(project_id: UUID, body: HypothesisInput, request: Request):
    return await call(HypothesisStore(store(request)).save, project_id, body)


@router.get("/projects/{project_id}/hypotheses", response_model=HypothesisList)
async def hypotheses(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(HypothesisStore(store(request)).list, project_id, offset, limit + 1)
    return HypothesisList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/hypotheses/{id}", response_model=StoredHypothesis)
async def hypothesis(id: UUID, request: Request):
    return await call(HypothesisStore(store(request)).get, id)


@router.get("/hypotheses/{id}/evidence", response_model=HypothesisEvidence)
async def evidence(id: UUID, request: Request):
    return HypothesisEvidence(items=await call(HypothesisStore(store(request)).evidence, id))


@router.post("/projects/{project_id}/corpora", response_model=StoredCorpus, status_code=201)
async def save_corpus(project_id: UUID, body: CorpusInput, request: Request):
    return await call(ValidationStore(store(request)).save_corpus, project_id, body)


@router.get("/projects/{project_id}/corpora", response_model=CorpusList)
async def corpora(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(ValidationStore(store(request)).corpora, project_id, offset, limit + 1)
    return CorpusList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/corpus-versions/{id}", response_model=StoredCorpus)
async def corpus(id: UUID, request: Request):
    return await call(ValidationStore(store(request)).corpus, id)


@router.post("/projects/{project_id}/validation-runs", response_model=JobSnapshot, status_code=202)
async def validate(project_id: UUID, body: RunInput, request: Request):
    projects = store(request)
    repository = ValidationStore(projects)
    snapshot = await call(repository.freeze, project_id, body)
    stage = projects.safe_path(project_id, f".staging/{uuid4()}")
    stage.mkdir()
    artifact = stage / "validation.jsonl"
    cleanup = functools.partial(shutil.rmtree, stage, ignore_errors=True)
    total = len(snapshot.sources) + sum(s.extent * 2 for c in snapshot.sources for s in c.streams)
    try:
        return request.app.state.jobs.create_import(
            validation_worker,
            (
                request.app.state.settings.database_url,
                str(projects.root),
                snapshot,
                str(artifact),
                request.app.state.settings.validation_limits,
            ),
            total,
            functools.partial(repository.publish, snapshot, artifact),
            cleanup,
            kind="corpus_validation",
        )
    except JobLimitError as exc:
        cleanup()
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        cleanup()
        raise


@router.get("/projects/{project_id}/validation-runs", response_model=ValidationRunList)
async def runs(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(ValidationStore(store(request)).runs, project_id, offset, limit + 1)
    return ValidationRunList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/validation-runs/{id}", response_model=ValidationRun)
async def run(id: UUID, request: Request):
    return await call(ValidationStore(store(request)).get, id)


@router.get("/validation-runs/{id}/currentness", response_model=Currentness)
async def currentness(id: UUID, request: Request):
    return await call(ValidationStore(store(request)).currentness, id)


@router.get("/validation-runs/{id}/results", response_model=ValidationResultList)
async def results(
    id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100, status: Status | None = None
):
    items = await call(ValidationStore(store(request)).results, id, offset, limit + 1, status)
    return ValidationResultList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/validation-runs/{id}/results/{result_id}", response_model=ValidationItem)
async def result(id: UUID, result_id: UUID, request: Request):
    return await call(ValidationStore(store(request)).result, id, result_id)


@router.get("/validation-runs/{id}/compare/{other_id}", response_model=Comparison)
async def comparison(
    id: UUID, other_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100
):
    return await call(ValidationStore(store(request)).comparison, id, other_id, offset, limit)
