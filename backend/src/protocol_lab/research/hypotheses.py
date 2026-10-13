"""Semantic hypotheses are authored claims, never automatic parser conclusions."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from protocol_lab.domain.models import Hypothesis, Record


class HypothesisInput(Record):
    statement: str = Field(min_length=1, max_length=10000)
    rationale: str = Field(min_length=1, max_length=10000)
    scope: str = Field(min_length=1, max_length=10000)
    observation_ids: tuple[UUID, ...] = Field(default=(), max_length=128)
    unknowns: tuple[str, ...] = Field(default=(), max_length=128)
    contradictions: tuple[str, ...] = Field(default=(), max_length=128)
    parent_id: UUID | None = None


class StoredHypothesis(Hypothesis):
    hypothesis_id: UUID
    parent_id: UUID | None
    created_at: datetime
