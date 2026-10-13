from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from protocol_lab.domain.models import Observation
from protocol_lab.research.hypotheses import StoredHypothesis
from protocol_lab.storage.database import HypothesisRow, ObservationRow


class HypothesisStore:
    def __init__(self, projects):
        self.projects, self.engine = projects, projects.engine

    def get(self, hypothesis_id):
        with Session(self.engine) as db:
            row = db.get(HypothesisRow, hypothesis_id)
            if row is None:
                raise KeyError(hypothesis_id)
            result = StoredHypothesis.model_validate(row.metadata_json)
        self.projects.get(result.project_id)
        return result

    def save(self, project_id, body):
        self.projects.get(project_id)
        parent = self.get(body.parent_id) if body.parent_id else None
        if parent and parent.project_id != project_id:
            raise ValueError("Hypothesis parent belongs to another project")
        if len(set(body.observation_ids)) != len(body.observation_ids):
            raise ValueError("Duplicate hypothesis evidence references")
        if any(
            not text.strip() or len(text) > 10000 for text in (*body.unknowns, *body.contradictions)
        ):
            raise ValueError(
                "Hypothesis unknowns/contradictions require nonempty text <=10000 characters"
            )
        with Session(self.engine) as db, db.begin():
            for observation_id in body.observation_ids:
                row = db.get(ObservationRow, observation_id)
                if row is None or row.project_id != project_id:
                    raise ValueError(
                        "Hypothesis evidence must reference existing observations in this project"
                    )
            result = StoredHypothesis(
                id=uuid4(),
                hypothesis_id=parent.hypothesis_id if parent else uuid4(),
                parent_id=body.parent_id,
                project_id=project_id,
                created_at=datetime.now(UTC),
                **body.model_dump(exclude={"parent_id"}),
            )
            db.add(
                HypothesisRow(
                    id=result.id,
                    hypothesis_id=result.hypothesis_id,
                    parent_id=result.parent_id,
                    project_id=project_id,
                    created_at=result.created_at,
                    metadata_json=result.model_dump(mode="json"),
                )
            )
        return result

    def list(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            return [
                StoredHypothesis.model_validate(row)
                for row in db.scalars(
                    select(HypothesisRow.metadata_json)
                    .where(HypothesisRow.project_id == project_id)
                    .order_by(HypothesisRow.created_at.desc(), HypothesisRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def evidence(self, hypothesis_id):
        hypothesis = self.get(hypothesis_id)
        with Session(self.engine) as db:
            result = []
            for id in hypothesis.observation_ids:
                row = db.get(ObservationRow, id)
                if row is None or row.project_id != hypothesis.project_id:
                    raise ValueError("Hypothesis observation is unavailable")
                result.append(Observation.model_validate(row.metadata_json))
            return result
