"""Local jobs produce complete, verified artifacts before atomic publication."""

import os
import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from protocol_lab.capture.index import WorkCancelled, sha256_file
from protocol_lab.reports.render import render_report
from protocol_lab.storage.database import ValidationRunRow, make_engine
from protocol_lab.storage.portable import pack, restore, snapshot, unpack, verify_bundle
from protocol_lab.storage.projects import ProjectStore, StorageError
from protocol_lab.storage.validation import ValidationStore
from protocol_lab.validation.models import ValidationRun


def validation_json(
    projects, run_id, output, cancelled=lambda: False, progress=lambda done, total, message: None
):
    repository = ValidationStore(projects)
    run = repository.get(run_id)
    with Session(projects.engine) as db:
        row = db.get(ValidationRunRow, run_id)
        path = projects.safe_path(run.snapshot.project_id, row.relative_path)
        expected = row.sha256
    if sha256_file(path) != expected:
        raise StorageError("Validation artifact checksum mismatch")
    output.write('{"format":"protocol-lab-validation","format_version":1,"run":')
    with path.open() as source:
        header = source.readline()
        if ValidationRun.model_validate_json(header) != run:
            raise StorageError("Validation artifact metadata mismatch")
        output.write(header.strip())
        output.write(',"results":[')
        first = True
        completed = 0
        total = sum(run.coverage.counts.values())
        for line in source:
            if cancelled():
                raise WorkCancelled
            if not first:
                output.write(",")
            first = False
            output.write(line.strip())
            completed += 1
            if completed % 100 == 0 or completed == total:
                progress(completed, total, "Exporting complete validation results (rows)")
    output.write("]}\n")
    if sha256_file(path) != expected:
        raise StorageError("Validation artifact changed; no export published")


def portability_worker(send, cancel, database_url, root, operation, project_id, stage, run_id=None):
    engine = None
    try:
        engine = make_engine(database_url)
        projects = ProjectStore(engine, Path(root))
        stage = Path(stage)

        def progress(done, total, message):
            send.send(
                (
                    "progress",
                    {
                        "completed": done,
                        "total": max(total, 1),
                        "message": message,
                    },
                )
            )

        if operation == "restore":
            bundle = unpack(stage / "upload.zip", stage / "bundle", cancel.is_set, progress)
            summary = {"outcome": "prepared", "project_id": str(bundle.project_id)}
        elif operation == "validation_json":
            with (stage / "validation.json").open("x") as output:
                validation_json(projects, run_id, output, cancel.is_set, progress)
            summary = {"outcome": "exported", "filename": "validation.json"}
        else:
            bundle = snapshot(projects, project_id, stage / "bundle", cancel.is_set, progress)
            summary = {
                "outcome": operation,
                "project_id": str(project_id),
                "table_counts": bundle.table_counts,
                "files": len(bundle.members),
            }
            if operation == "export":
                pack(stage / "bundle", stage / "project.zip", cancel.is_set, progress)
                summary["filename"] = "project.zip"
            elif operation == "report":
                with (stage / "report.md").open("x") as output:
                    render_report(stage / "bundle", output)
                summary["filename"] = "report.md"
        if cancel.is_set():
            raise WorkCancelled
        send.send(("prepared", summary))
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError) as exc:
        send.send(("failed", f"{exc}; previous projects remain usable"))
    except Exception:
        send.send(("failed", "Project operation failed; previous projects remain usable"))
    finally:
        if engine:
            engine.dispose()
        send.close()


def publish_operation(projects, project_id, operation, artifact_id, stage, summary):
    stage = Path(stage)
    if operation == "restore":
        return restore(projects, stage / "bundle")
    if operation == "verify":
        verify_bundle(stage / "bundle")
        return {**summary, "outcome": "verified"}
    if operation == "save":
        verify_bundle(stage / "bundle")
        destination = projects.safe_path(project_id, f"checkpoints/{artifact_id}")
        destination.parent.mkdir(exist_ok=True)
        # The UUID directory is new. No older snapshot or research is replaced.
        if destination.exists():
            raise StorageError("Checkpoint already exists; refusing overwrite")
        os.rename(stage / "bundle", destination)
        return {**summary, "outcome": "saved", "checkpoint": f"checkpoints/{artifact_id}"}
    filename = summary["filename"]
    destination = projects.safe_path(project_id, f"exports/{artifact_id}")
    destination.mkdir(parents=True)
    try:
        shutil.copyfile(stage / filename, destination / filename)
        (destination / filename).chmod(0o444)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {
        **summary,
        "outcome": "exported",
        "download_url": f"/api/v1/projects/{project_id}/exports/{artifact_id}/{filename}",
    }
