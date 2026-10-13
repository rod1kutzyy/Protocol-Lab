"""Action evidence persists independently of mutable clock correlation settings."""

import os
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import Field
from sqlalchemy import insert, select, text, update
from sqlalchemy.orm import Session

from protocol_lab.capture.index import sha256_file
from protocol_lab.domain.models import Observation, Record
from protocol_lab.research.action_logs import ActionEvent, LogMapping
from protocol_lab.storage.database import (
    ActionLinkRow,
    ActionLogRow,
    ActionRow,
    ObservationRow,
    PacketRow,
)
from protocol_lab.storage.projects import StorageError
from protocol_lab.storage.reconstruction import ReconstructionStore


class StoredLog(Record):
    id: UUID
    project_id: UUID
    sha256: str
    relative_path: str
    format: str
    mapping: LogMapping
    row_count: int
    event_count: int
    rejected_rows: int
    diagnostics: list[dict]
    diagnostics_complete: bool
    clock_offset_ns: str = "0"
    clock_revision: int = 1


class ClockUpdate(Record):
    clock_offset_ns: str = Field(pattern=r"^-?\d{1,19}$")
    expected_revision: int = Field(ge=1)


class ActionLink(Record):
    id: UUID
    action_id: UUID
    observation: Observation


class CorrelatedActions(Record):
    items: list[ActionEvent]
    next_offset: int | None
    source_start_ns: str | None
    source_end_ns: str | None
    unknown_packet_timestamps: int
    method: str = "time_window_only_not_semantic_proof"


def log_record(row):
    return StoredLog(
        **row.metadata_json,
        clock_offset_ns=str(int(row.clock_offset_ns)),
        clock_revision=row.clock_revision,
    )


class ResearchStore:
    def __init__(self, projects):
        self.projects = projects
        self.engine = projects.engine
        self.tcp = ReconstructionStore(projects)

    def publish_log(
        self, project_id, log_id, source: Path, events: Path, checksum, format, mapping, summary
    ):
        self.projects.get(project_id)
        if sha256_file(source) != checksum:
            raise StorageError("Staged log checksum changed; no log published")
        relative = f"sources/action-{checksum}.{format}"
        destination = self.projects.safe_path(project_id, relative)
        with Session(self.engine) as db, db.begin():
            key = int.from_bytes(project_id.bytes[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            old = db.scalar(
                select(ActionLogRow).where(
                    ActionLogRow.project_id == project_id, ActionLogRow.sha256 == checksum
                )
            )
            if old:
                path = self.projects.safe_path(project_id, old.metadata_json["relative_path"])
                if not path.exists() or sha256_file(path) != checksum:
                    raise StorageError("Existing action-log source checksum mismatch")
                return dict(
                    outcome="already_imported",
                    log_id=str(old.id),
                    mapping=old.metadata_json["mapping"],
                    requested_mapping=mapping.model_dump(),
                )
            if destination.exists():
                if sha256_file(destination) != checksum:
                    raise StorageError("Action-log destination checksum mismatch")
            else:
                os.link(source, destination)
                destination.chmod(0o444)
            record = StoredLog(
                id=log_id,
                project_id=project_id,
                sha256=checksum,
                relative_path=relative,
                format=format,
                mapping=mapping,
                **summary,
            )
            db.add(
                ActionLogRow(
                    id=log_id,
                    project_id=project_id,
                    sha256=checksum,
                    clock_offset_ns=0,
                    clock_revision=1,
                    metadata_json=record.model_dump(
                        mode="json", exclude={"clock_offset_ns", "clock_revision"}
                    ),
                )
            )
            db.flush()
            batch, count = [], 0
            with events.open() as file:
                for line in file:
                    event = ActionEvent.model_validate_json(line)
                    if event.log_id != log_id:
                        raise StorageError("Staged action-log identity mismatch")
                    batch.append(
                        dict(
                            id=event.id,
                            log_id=log_id,
                            row_index=event.row_index,
                            timestamp_ns=int(event.timestamp_ns),
                            metadata_json=event.model_dump(mode="json"),
                        )
                    )
                    count += 1
                    if len(batch) == 1000:
                        db.execute(insert(ActionRow), batch)
                        batch = []
                if batch:
                    db.execute(insert(ActionRow), batch)
            if count != summary["event_count"]:
                raise StorageError("Staged action count mismatch; no log published")
        return dict(outcome="imported", log_id=str(log_id), **summary)

    def logs(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            return [
                log_record(row)
                for row in db.scalars(
                    select(ActionLogRow)
                    .where(ActionLogRow.project_id == project_id)
                    .order_by(ActionLogRow.id)
                    .offset(offset)
                    .limit(limit)
                )
            ]

    def clock(self, log_id, body):
        if abs(int(body.clock_offset_ns)) > 2**63 - 1:
            raise ValueError("Clock offset out of range")
        with Session(self.engine) as db, db.begin():
            row = db.get(ActionLogRow, log_id)
            if row is None:
                raise KeyError(log_id)
            self.projects.get(row.project_id)
            result = db.execute(
                update(ActionLogRow)
                .where(
                    ActionLogRow.id == log_id, ActionLogRow.clock_revision == body.expected_revision
                )
                .values(
                    clock_offset_ns=int(body.clock_offset_ns),
                    clock_revision=body.expected_revision + 1,
                )
            )
            if result.rowcount != 1:
                raise StorageError("Clock settings changed; reload the log before updating")
            db.expire(row)
            return log_record(row)

    def actions(self, project_id, offset, limit, log_id=None):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            query = (
                select(ActionRow.metadata_json)
                .join(ActionLogRow)
                .where(ActionLogRow.project_id == project_id)
            )
            if log_id:
                query = query.where(ActionRow.log_id == log_id)
            return [
                ActionEvent.model_validate(value)
                for value in db.scalars(
                    query.order_by(ActionRow.timestamp_ns, ActionRow.id).offset(offset).limit(limit)
                )
            ]

    def correlate(self, stream_id, offset, length, window_ns, page, limit):
        ranges = self.tcp.ranges(stream_id, offset, length)
        packet_ids = {e.packet_id for b in ranges.blocks for v in b.variants for e in v.sources}
        with Session(self.engine) as db:
            first, last = self.tcp.packet_times(db, packet_ids)
            unknown = 0
            ids = list(packet_ids)
            for start in range(0, len(ids), 1000):
                values = db.scalars(
                    select(PacketRow.metadata_json["timestamp_ns"].astext).where(
                        PacketRow.id.in_(ids[start : start + 1000])
                    )
                )
                unknown += sum(value is None for value in values)
            if first is None:
                return CorrelatedActions(
                    items=[],
                    next_offset=None,
                    source_start_ns=None,
                    source_end_ns=None,
                    unknown_packet_timestamps=unknown,
                )
            session = self.tcp.session(self.tcp.stream(stream_id).session_id)
            project_id = self.projects.get_capture(session.capture_id).project_id
            adjusted = ActionRow.timestamp_ns + ActionLogRow.clock_offset_ns
            query = (
                select(ActionRow.metadata_json)
                .join(ActionLogRow)
                .where(
                    ActionLogRow.project_id == project_id,
                    adjusted >= first - window_ns,
                    adjusted <= last + window_ns,
                )
            )
            items = [
                ActionEvent.model_validate(value)
                for value in db.scalars(
                    query.order_by(adjusted, ActionRow.id).offset(page).limit(limit + 1)
                )
            ]
        return CorrelatedActions(
            items=items[:limit],
            next_offset=page + limit if len(items) > limit else None,
            source_start_ns=str(first),
            source_end_ns=str(last),
            unknown_packet_timestamps=unknown,
        )

    def link(self, project_id, action_id, body):
        observation = self.tcp.build_observation(project_id, body)
        with Session(self.engine) as db, db.begin():
            action = db.get(ActionRow, action_id)
            if action is None:
                raise KeyError(action_id)
            log = db.get(ActionLogRow, action.log_id)
            if log.project_id != project_id:
                raise ValueError("Action belongs to another project")
            db.add(
                ObservationRow(
                    id=observation.id,
                    project_id=project_id,
                    metadata_json=observation.model_dump(mode="json"),
                )
            )
            db.flush()
            link_id = uuid4()
            db.add(
                ActionLinkRow(
                    id=link_id,
                    project_id=project_id,
                    action_id=action_id,
                    observation_id=observation.id,
                )
            )
        return ActionLink(id=link_id, action_id=action_id, observation=observation)

    def links(self, project_id, offset, limit):
        self.projects.get(project_id)
        with Session(self.engine) as db:
            rows = db.execute(
                select(ActionLinkRow, ObservationRow.metadata_json)
                .join(ObservationRow)
                .where(ActionLinkRow.project_id == project_id)
                .order_by(ActionLinkRow.id)
                .offset(offset)
                .limit(limit)
            )
            return [
                ActionLink(
                    id=row.id,
                    action_id=row.action_id,
                    observation=Observation.model_validate(metadata),
                )
                for row, metadata in rows
            ]
