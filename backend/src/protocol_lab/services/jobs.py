"""Local bounded process jobs. All registry mutation happens on the API event loop."""

import asyncio
import multiprocessing as mp
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

JobStatus = Literal[
    "queued", "running", "cancelling", "committing", "cancelled", "succeeded", "failed"
]
TERMINAL = {"cancelled", "succeeded", "failed"}


class DiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: int = Field(default=20, ge=1, le=100)
    delay_ms: int = Field(default=100, ge=0, le=300)


class JobSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID
    kind: Literal[
        "worker_diagnostic",
        "capture_import",
        "tcp_reconstruction",
        "stream_search",
        "action_log_import",
        "stream_framing",
        "message_interpretation",
        "corpus_validation",
        "project_operation",
        "project_restore",
    ] = "worker_diagnostic"
    status: JobStatus = "queued"
    completed: int = 0
    total: int
    message: str = "Waiting for local worker"
    revision: int = 1
    created_at: datetime
    updated_at: datetime
    result: dict[str, Any] | None = None
    error: str | None = None


def diagnostic_worker(send: Connection, cancel: Any, request: DiagnosticRequest) -> None:
    """No protocol data: exercises process isolation, progress and cooperative cancellation."""
    try:
        for step in range(1, request.steps + 1):
            if cancel.wait(request.delay_ms / 1000):
                send.send(("cancelled", None))
                return
            send.send(("progress", step))
        send.send(("succeeded", {"checked_steps": request.steps}))
    except Exception:
        # Never leak payloads, paths or exception arguments through the public API.
        send.send(("failed", "Worker failed; no completed artifact was published"))
    finally:
        send.close()


@dataclass
class Job:
    snapshot: JobSnapshot
    request: DiagnosticRequest | None
    target: Callable = diagnostic_worker
    args: tuple = ()
    finalize: Callable | None = None
    cleanup: Callable | None = None
    publication: asyncio.Task | None = None
    process: Any = None
    receive: Connection | None = None
    cancel_event: Any = None
    cancel_at: float | None = None


class JobLimitError(Exception):
    pass


class JobManager:
    def __init__(self, max_workers: int = 2, max_jobs: int = 128):
        self.max_workers = max_workers
        self.max_jobs = max_jobs
        self.jobs: dict[UUID, Job] = {}
        self.context = mp.get_context("spawn")
        self.task: asyncio.Task | None = None

    async def start(self):
        self.task = asyncio.create_task(self._pump())

    async def close(self):
        # Publication is non-cancellable: finish its DB transaction before cleanup.
        while any(job.snapshot.status == "committing" for job in self.jobs.values()):
            await asyncio.sleep(0.02)
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        for job in self.jobs.values():
            if job.process:
                if job.process.is_alive():
                    job.process.terminate()
                await asyncio.to_thread(job.process.join, 2)
                job.process.close()
            if job.receive:
                job.receive.close()
            if job.cleanup:
                job.cleanup()

    def create(self, request: DiagnosticRequest) -> JobSnapshot:
        if len(self.jobs) >= self.max_jobs:
            raise JobLimitError("Job registry limit reached; restart the development API")
        now = datetime.now(UTC)
        snapshot = JobSnapshot(id=uuid4(), total=request.steps, created_at=now, updated_at=now)
        self.jobs[snapshot.id] = Job(snapshot, request)
        return snapshot

    def create_import(
        self,
        target: Callable,
        args: tuple,
        total: int,
        finalize: Callable,
        cleanup: Callable,
        kind: Literal[
            "capture_import",
            "tcp_reconstruction",
            "stream_search",
            "action_log_import",
            "stream_framing",
            "message_interpretation",
            "corpus_validation",
            "project_operation",
            "project_restore",
        ] = "capture_import",
    ) -> JobSnapshot:
        if len(self.jobs) >= self.max_jobs:
            raise JobLimitError("Job registry limit reached; restart the development API")
        now = datetime.now(UTC)
        snapshot = JobSnapshot(id=uuid4(), kind=kind, total=total, created_at=now, updated_at=now)
        self.jobs[snapshot.id] = Job(snapshot, None, target, args, finalize, cleanup)
        return snapshot

    def get(self, job_id: UUID) -> JobSnapshot:
        return self.jobs[job_id].snapshot

    def _update(self, job: Job, **changes):
        job.snapshot = job.snapshot.model_copy(
            update={
                **changes,
                "revision": job.snapshot.revision + 1,
                "updated_at": datetime.now(UTC),
            }
        )

    def cancel(self, job_id: UUID) -> JobSnapshot:
        job = self.jobs[job_id]
        if job.snapshot.status == "queued":
            self._update(job, status="cancelled", message="Cancelled before start")
            if job.cleanup:
                job.cleanup()
        elif job.snapshot.status == "running":
            job.cancel_event.set()
            job.cancel_at = time.monotonic()
            self._update(job, status="cancelling", message="Cancellation requested")
        return job.snapshot

    async def _publish(self, job: Job, summary: dict):
        # Keep draining/cancelling other worker processes while PostgreSQL commits.
        try:
            result = await asyncio.to_thread(job.finalize, summary)
        except Exception as exc:
            from protocol_lab.capture.index import CaptureError
            from protocol_lab.storage.projects import StorageError

            error = (
                str(exc)
                if isinstance(exc, (CaptureError, StorageError))
                else "Publication failed; no completed result published"
            )
            self._update(
                job, status="failed", error=error, result=None, message="Publication failed"
            )
        else:
            self._update(
                job,
                status="succeeded",
                result=result,
                completed=job.snapshot.total,
                message="Source already imported"
                if result["outcome"] == "already_imported"
                else "TCP reconstruction complete"
                if job.snapshot.kind == "tcp_reconstruction"
                else "Stream framing complete"
                if job.snapshot.kind == "stream_framing"
                else "Corpus validation complete"
                if job.snapshot.kind == "corpus_validation"
                else "Message interpretation complete"
                if job.snapshot.kind == "message_interpretation"
                else "Action-log import complete"
                if job.snapshot.kind == "action_log_import"
                else "Project operation complete"
                if job.snapshot.kind in {"project_operation", "project_restore"}
                else "Capture import complete",
            )
        finally:
            if job.cleanup:
                job.cleanup()

    async def _pump(self):
        while True:
            active = sum(
                job.process is not None or job.snapshot.status == "committing"
                for job in self.jobs.values()
            )
            for job in list(self.jobs.values()):
                if job.snapshot.status == "queued" and active < self.max_workers:
                    receive, send = self.context.Pipe(duplex=False)
                    job.receive = receive
                    job.cancel_event = self.context.Event()
                    job.process = self.context.Process(
                        target=job.target,
                        args=(
                            send,
                            job.cancel_event,
                            *(job.args if job.request is None else (job.request,)),
                        ),
                    )
                    try:
                        job.process.start()
                    except Exception:
                        job.process = None
                        receive.close()
                        if job.cleanup:
                            job.cleanup()
                        self._update(
                            job,
                            status="failed",
                            error="Unable to start local worker",
                            message="No completed artifact was published",
                        )
                    else:
                        self._update(job, status="running", message="Checking local worker")
                        active += 1
                    finally:
                        send.close()
                if job.process is None:
                    continue
                exited = not job.process.is_alive()
                while job.receive and job.receive.poll():
                    try:
                        kind, value = job.receive.recv()
                    except EOFError:
                        break
                    if job.snapshot.status in TERMINAL:
                        continue
                    if kind == "progress":
                        self._update(job, **value) if isinstance(value, dict) else self._update(
                            job, completed=value
                        )
                    elif kind == "prepared":
                        if job.snapshot.status == "cancelling":
                            self._update(
                                job,
                                status="cancelled",
                                result=None,
                                message="Cancelled; no capture published",
                            )
                        else:
                            self._update(
                                job,
                                status="committing",
                                message="Publishing immutable result; cancellation closed",
                            )
                            job.publication = asyncio.create_task(self._publish(job, value))
                    elif kind == "succeeded" and job.snapshot.status != "cancelling":
                        self._update(
                            job, status="succeeded", result=value, message="Operation complete"
                        )
                    elif kind in {"cancelled", "succeeded"}:
                        self._update(
                            job,
                            status="cancelled",
                            result=None,
                            message="Cancelled; no result published",
                        )
                    else:
                        self._update(
                            job, status="failed", error=value, result=None, message="Worker failed"
                        )
                if (
                    job.cancel_at
                    and time.monotonic() - job.cancel_at > 2
                    and job.process.is_alive()
                ):
                    job.process.terminate()
                if exited:
                    job.process.join(timeout=0)
                    job.process.close()
                    job.process = None
                    if job.receive:
                        job.receive.close()
                        job.receive = None
                    if job.snapshot.status not in TERMINAL and job.snapshot.status != "committing":
                        status = "cancelled" if job.cancel_at else "failed"
                        self._update(
                            job,
                            status=status,
                            result=None,
                            error=None if job.cancel_at else "Worker exited without a result",
                            message="No completed artifact was published",
                        )
                    if job.cleanup and job.publication is None:
                        job.cleanup()
                    if job.snapshot.status != "committing":
                        active -= 1
            await asyncio.sleep(0.02)
