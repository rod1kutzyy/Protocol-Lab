"""Cancellable inference process workers and bounded immutable artifact preparation."""

import json
import os
from pathlib import Path

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.inference.engine import discover, evaluate, partition
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.inference import InferenceStore
from protocol_lab.storage.projects import ProjectStore, StorageError


def write_artifact(path, header, candidates, evidence, maximum, cancelled):
    budget = ResultBudget(ResultLimits(max_bytes=maximum))
    with Path(path).open("xb") as file:

        def write(line):
            if cancelled():
                raise WorkCancelled
            budget.consume(line)
            file.write(line.encode())

        write(header.model_dump_json() + "\n")
        for kind, records in (("candidate", candidates), ("evidence", evidence)):
            for record in records:
                write(
                    json.dumps(
                        {"kind": kind, "value": record.model_dump(mode="json")},
                        separators=(",", ":"),
                    )
                    + "\n"
                )
        file.flush()
        os.fsync(file.fileno())


def inference_worker(
    send, cancel, database_url, project_root, snapshot, artifact, run_id, parent_id
):
    engine = None
    try:
        engine = make_engine(database_url)
        repository = InferenceStore(ProjectStore(engine, Path(project_root)))
        repository.verify_inputs(snapshot)

        def progress(message, completed, total):
            send.send(("progress", dict(message=message, completed=completed, total=total)))

        with repository.inputs(snapshot) as inputs:
            run, candidates, evidence = discover(
                snapshot, inputs, run_id, parent_id, cancel.is_set, progress
            )
        repository.verify_inputs(snapshot)
        write_artifact(
            artifact,
            run,
            candidates,
            evidence,
            snapshot.spec.budget.max_evidence_bytes,
            cancel.is_set,
        )
        if cancel.is_set():
            raise WorkCancelled
        send.send(
            ("prepared", dict(candidate_count=len(candidates), search_complete=run.search_complete))
        )
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError, OSError) as exc:
        send.send(
            (
                "failed",
                f"Inference corpus {snapshot.corpus.id}: {exc}; previous results remain usable",
            )
        )
    except Exception:
        send.send(("failed", "Inference worker failed; no completed artifact published"))
    finally:
        if engine:
            engine.dispose()
        send.close()


def evaluation_worker(
    send, cancel, database_url, project_root, snapshot, artifact, candidate, holdout
):
    engine = None
    try:
        engine = make_engine(database_url)
        repository = InferenceStore(ProjectStore(engine, Path(project_root)))
        repository.verify_inputs(snapshot)
        independence, reason = repository.independence(candidate.run_id, snapshot, holdout)
        send.send(
            (
                "progress",
                dict(
                    message="evaluation: frozen rule, no parameter search",
                    completed=0,
                    total=sum(s.extent for c in snapshot.sources for s in c.streams),
                ),
            )
        )
        with repository.inputs(snapshot) as inputs:
            if holdout:
                inputs = partition(snapshot, inputs, "holdout", include_excluded=True)
            if independence == "independent":
                from protocol_lab.inference.independence import recording_overlap

                original = repository.get(candidate.run_id).snapshot
                with repository.inputs(original) as original_inputs:
                    discovery_inputs = partition(original, original_inputs, "discovery")
                    independence, overlap_reason = recording_overlap(
                        discovery_inputs,
                        inputs,
                        snapshot.spec.budget,
                        cancel.is_set,
                    )
                reason += "; " + overlap_reason
            record, evidence = evaluate(
                snapshot, candidate, inputs, candidate.run_id, cancel.is_set, independence, reason
            )
            record = record.model_copy(update={"target_side": "holdout" if holdout else "corpus"})
        repository.verify_inputs(snapshot)
        write_artifact(
            artifact, record, (), evidence, snapshot.spec.budget.max_evidence_bytes, cancel.is_set
        )
        if cancel.is_set():
            raise WorkCancelled
        send.send(("prepared", dict(complete=record.complete)))
    except WorkCancelled:
        send.send(("cancelled", None))
    except (StorageError, ValueError, OSError) as exc:
        send.send(("failed", f"Candidate {candidate.id}: {exc}; previous results remain usable"))
    except Exception:
        send.send(("failed", "Candidate evaluation failed; no completed artifact published"))
    finally:
        if engine:
            engine.dispose()
        send.close()
