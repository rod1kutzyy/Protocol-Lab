"""A0 advertises schemas, not an implemented automatic analysis service."""

import functools
import shutil
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field, ValidationError

from protocol_lab.api.projects import Limit, Offset, call, store
from protocol_lab.domain.models import Record
from protocol_lab.inference.compilation import model_draft
from protocol_lab.inference.document import MAX_DOCUMENT_BYTES, load_document
from protocol_lab.inference.engine import DETECTORS
from protocol_lab.inference.models import (
    CONTRACT_VERSION,
    FAMILIES,
    CandidateEvidence,
    Family,
    InferenceCandidate,
    InferenceRun,
    InferenceSpec,
    SearchBudget,
    SearchSpace,
    json_schema,
)
from protocol_lab.inference.results import (
    CandidateSummary,
    DraftResult,
    EvaluationRecord,
    EvaluationRequest,
    InferenceCurrentness,
    InferenceRequest,
    RunSummary,
)
from protocol_lab.services.inference import evaluation_worker, inference_worker
from protocol_lab.services.jobs import JobLimitError, JobSnapshot
from protocol_lab.storage.inference import InferenceStore
from protocol_lab.validation.models import Status

router = APIRouter(prefix="/api/v1", tags=["inference"])
SchemaName = Literal[
    "spec",
    "snapshot",
    "rule",
    "candidate",
    "run",
    "evidence",
    "evaluation",
    "decision",
    "transform",
]


class DetectorCapability(Record):
    family: Family
    available: bool = False
    implementation_version: str | None = None


class InferenceCapabilities(Record):
    stage: Literal["A4"] = "A4"
    contract_version: str = CONTRACT_VERSION
    analysis_available: Literal[True] = True
    scope_verification_available: Literal[True] = True
    budget_profile: str = "bounded_a4"
    detectors: tuple[DetectorCapability, ...]
    default_budget: SearchBudget = Field(default_factory=SearchBudget)
    default_search: SearchSpace = Field(default_factory=SearchSpace)
    schema_names: tuple[SchemaName, ...]


class SpecDocument(Record):
    document_json: str = Field(max_length=MAX_DOCUMENT_BYTES)


class SpecIssue(Record):
    path: str
    message: str


class SpecCheck(Record):
    valid: bool
    scope_verified: Literal[False] = False
    spec: InferenceSpec | None = None
    issues: tuple[SpecIssue, ...] = ()


@router.get("/inference/capabilities", response_model=InferenceCapabilities)
async def capabilities():
    from protocol_lab.inference.models import SCHEMAS

    return InferenceCapabilities(
        detectors=tuple(
            DetectorCapability(
                family=name, available=name in DETECTORS, implementation_version=DETECTORS.get(name)
            )
            for name in FAMILIES
        ),
        schema_names=tuple(SCHEMAS),
    )


@router.get("/inference/schemas/{name}")
async def schema(name: SchemaName) -> dict:
    return json_schema(name)


@router.get("/inference/checksum-registry")
async def checksum_registry() -> dict:
    from dataclasses import asdict

    from protocol_lab.interpretation.checksums import REGISTRY, VERSION

    return {
        "version": VERSION,
        "check_vector_hex": b"123456789".hex(),
        "algorithms": {name: asdict(spec) for name, spec in REGISTRY.items()},
    }


@router.post("/inference/spec/check", response_model=SpecCheck)
async def check(body: SpecDocument):
    try:
        return SpecCheck(valid=True, spec=load_document(body.document_json))
    except ValidationError as exc:
        return SpecCheck(
            valid=False,
            issues=tuple(
                SpecIssue(path=".".join(map(str, e["loc"])), message=e["msg"])
                for e in exc.errors(include_input=False, include_context=False)
            ),
        )
    except ValueError as exc:
        return SpecCheck(valid=False, issues=(SpecIssue(path="", message=str(exc)),))


class InferenceRunList(Record):
    items: list[RunSummary]
    next_offset: int | None


class CandidateList(Record):
    items: list[CandidateSummary]
    total: int
    next_offset: int | None


class EvidenceList(Record):
    items: list[CandidateEvidence]
    total: int
    next_offset: int | None


class EvaluationList(Record):
    items: list[EvaluationRecord]
    next_offset: int | None


def start_job(request, repository, snapshot, target, args, finalize, kind):
    stage = repository.projects.safe_path(snapshot.project_id, f".staging/{uuid4()}")
    stage.mkdir()
    artifact = stage / "inference.jsonl"
    cleanup = functools.partial(shutil.rmtree, stage, ignore_errors=True)
    try:
        return request.app.state.jobs.create_import(
            target,
            (
                request.app.state.settings.database_url,
                str(repository.projects.root),
                snapshot,
                str(artifact),
                *args,
            ),
            1,
            functools.partial(finalize, snapshot, artifact),
            cleanup,
            kind=kind,
        )
    except JobLimitError as exc:
        cleanup()
        raise HTTPException(429, str(exc)) from None
    except BaseException:
        cleanup()
        raise


@router.post("/projects/{project_id}/inference-runs", response_model=JobSnapshot, status_code=202)
async def discover(project_id: UUID, body: InferenceRequest, request: Request):
    repository = InferenceStore(store(request))
    spec = await call(load_document, body.document_json)
    if spec.mode != "discover":
        raise HTTPException(422, "Use the candidate evaluation endpoint for fixed-rule checks")
    snapshot = await call(repository.freeze, project_id, spec, body.parent_id)
    return start_job(
        request,
        repository,
        snapshot,
        inference_worker,
        (uuid4(), body.parent_id),
        repository.publish,
        "protocol_inference",
    )


@router.get("/projects/{project_id}/inference-runs", response_model=InferenceRunList)
async def runs(project_id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(InferenceStore(store(request)).runs, project_id, offset, limit + 1)
    return InferenceRunList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/inference-runs/{id}", response_model=InferenceRun)
async def run(id: UUID, request: Request):
    return await call(InferenceStore(store(request)).get, id)


@router.get("/inference-runs/{id}/currentness", response_model=InferenceCurrentness)
async def currentness(id: UUID, request: Request):
    return await call(InferenceStore(store(request)).currentness, id)


@router.get("/inference-runs/{id}/candidates", response_model=CandidateList)
async def candidates(
    id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100, family: Family | None = None
):
    items, total = await call(InferenceStore(store(request)).candidates, id, offset, limit, family)
    return CandidateList(
        items=items, total=total, next_offset=offset + limit if offset + limit < total else None
    )


@router.get("/inference-candidates/{id}", response_model=InferenceCandidate)
async def candidate(id: UUID, request: Request):
    return await call(InferenceStore(store(request)).candidate, id)


@router.get("/inference-candidates/{id}/evidence", response_model=EvidenceList)
async def evidence(
    id: UUID,
    request: Request,
    offset: Offset = 0,
    limit: Limit = 100,
    status: Status | None = None,
    evaluation_id: UUID | None = None,
):
    items, total = await call(
        InferenceStore(store(request)).evidence, id, offset, limit, status, evaluation_id
    )
    return EvidenceList(
        items=items, total=total, next_offset=offset + limit if offset + limit < total else None
    )


@router.post("/inference-candidates/{id}/model-draft", response_model=DraftResult)
async def draft(id: UUID, request: Request):
    return model_draft(await call(InferenceStore(store(request)).candidate, id))


@router.post("/inference-candidates/{id}/evaluations", response_model=JobSnapshot, status_code=202)
async def evaluate_candidate(id: UUID, body: EvaluationRequest, request: Request):
    repository = InferenceStore(store(request))
    if body.holdout == bool(body.corpus_version_id):
        raise HTTPException(422, "Select exactly one: saved holdout or a target corpus version")
    snapshot, candidate = await call(repository.freeze_evaluation, id, body.corpus_version_id)
    from protocol_lab.inference.models import FramingCandidateRule

    if (
        not isinstance(candidate.rule, FramingCandidateRule)
        and getattr(candidate.rule, "framing", None) is None
    ):
        raise HTTPException(
            422,
            "This rule has no frozen framing dependency for typed corpus evaluation",
        )
    return start_job(
        request,
        repository,
        snapshot,
        evaluation_worker,
        (candidate, body.holdout),
        repository.publish_evaluation,
        "inference_evaluation",
    )


@router.get("/inference-candidates/{id}/evaluations", response_model=EvaluationList)
async def evaluations(id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100):
    items = await call(InferenceStore(store(request)).evaluations, id, offset, limit + 1)
    return EvaluationList(
        items=items[:limit], next_offset=offset + limit if len(items) > limit else None
    )


@router.get("/inference-evaluations/{id}", response_model=EvaluationRecord)
async def evaluation(id: UUID, request: Request):
    return await call(InferenceStore(store(request)).evaluation, id)


@router.get("/inference-evaluations/{id}/results", response_model=EvidenceList)
async def evaluation_results(
    id: UUID, request: Request, offset: Offset = 0, limit: Limit = 100, status: Status | None = None
):
    repository = InferenceStore(store(request))
    record = await call(repository.evaluation, id)
    items, total = await call(
        repository.evidence, record.evaluation.candidate_id, offset, limit, status, id
    )
    return EvidenceList(
        items=items, total=total, next_offset=offset + limit if offset + limit < total else None
    )
