"""Inference publication and adapter contracts with backward-compatible records."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from protocol_lab.domain.models import Record, Sha256, StreamRange
from protocol_lab.inference.models import (
    CandidateEvaluation,
    Count,
    Family,
    InferenceCoverage,
    InferenceMetrics,
    Text,
)


class EvaluationRecord(Record):
    evaluation: CandidateEvaluation
    created_at: datetime
    discovery_run_id: UUID
    complete: bool
    coverage: InferenceCoverage
    diagnostics: tuple[Text, ...] = ()
    evidence_count: Count
    target_side: Literal["holdout", "corpus"] = "corpus"


class InferenceCurrentness(Record):
    checked_at: datetime
    stale: bool
    reasons: tuple[str, ...]
    details: tuple[str, ...] = ()


class RunSummary(Record):
    id: UUID
    created_at: datetime
    corpus_name: str
    corpus_version_id: UUID
    candidate_count: Count
    search_complete: bool
    semantic_sha256: Sha256 | None


class CandidateSummary(Record):
    id: UUID
    run_id: UUID
    family: Family
    kind: str
    rule_sha256: Sha256
    metrics: InferenceMetrics
    rationale: str
    compiler_support: str
    dependency_ids: tuple[UUID, ...]


class DraftResult(Record):
    candidate_id: UUID
    compilable: bool
    document_json: str | None = None
    diagnostics: tuple[str, ...]


class EvaluationRequest(Record):
    corpus_version_id: UUID | None = None
    holdout: bool = False


class InferenceRequest(Record):
    document_json: str = Field(max_length=524288)
    parent_id: UUID | None = None


class SearchRange(Record):
    anchor: StreamRange
    scanned: bool
    diagnostic: str
