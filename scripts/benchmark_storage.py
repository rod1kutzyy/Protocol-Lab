"""Measure PostgreSQL publication/validation/portability on the generated workload.

Creates and drops only two UUID schemas in an explicitly selected localhost test DB.
Each measured operation runs in a fresh process; research databases are never selected.
"""

import argparse
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path
from uuid import UUID, uuid4

from benchmark import CAPTURE_ID, model
from protocol_lab.capture.index import IndexSettings
from protocol_lab.services.validation import validation_worker
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.interpretations import InterpretationStore
from protocol_lab.storage.portable import pack, restore, snapshot, unpack, verify_bundle
from protocol_lab.storage.projects import ProjectStore
from protocol_lab.storage.reconstruction import ReconstructionStore
from protocol_lab.storage.validation import ValidationStore
from protocol_lab.validation.models import CorpusInput, RunInput, RunSnapshot
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = [
    "import_publication",
    "reconstruction_publication",
    "validation",
    "validation_publication",
    "reads",
    "snapshot",
    "zip",
    "verify",
    "restore",
]


class Sink:
    def __init__(self):
        self.summary = None

    def send(self, value):
        kind, body = value
        if kind == "prepared":
            self.summary = body
        elif kind == "failed":
            raise ValueError(body)

    def close(self):
        pass


class Cancellation:
    @staticmethod
    def is_set():
        return False


def worker(operation, workload, output):
    context_path = output / "context.json"
    context = json.loads(context_path.read_text()) if context_path.exists() else {}
    engine = make_engine(os.environ["PROTOCOL_LAB_DATABASE_URL"])
    projects = ProjectStore(engine, output / "projects")
    expected = json.loads((workload / "workload.json").read_text())
    start = time.perf_counter()
    details = {}
    try:
        if operation == "import_publication":
            project = projects.create("Synthetic control benchmark")
            context["project"] = str(project.id)
            stage = projects.safe_path(project.id, ".staging/benchmark")
            stage.mkdir()
            source = stage / "source"
            shutil.copyfile(workload / "control.pcap", source)
            result = projects.finalize_import(
                project.id,
                CAPTURE_ID,
                source,
                workload / "packets.jsonl",
                expected["sha256"],
                "pcap",
                IndexSettings(),
                {"packet_count": expected["packets"], "diagnostics": {}},
            )
            assert result["outcome"] == "imported"
            details = {"packets": result["packet_count"]}
        elif operation == "reconstruction_publication":
            artifact = projects.safe_path(
                UUID(context["project"]), ".staging/reconstruction.json"
            )
            shutil.copyfile(workload / "reconstruction.json", artifact)
            result = ReconstructionStore(projects).publish(
                CAPTURE_ID,
                artifact,
                {
                    "session_count": expected["connections"],
                    "excluded_packet_count": 0,
                    "version": "tcp-v1",
                },
            )
            assert result["outcome"] == "reconstructed"
            session = ReconstructionStore(projects).sessions(CAPTURE_ID, 0, 1)[0]
            stream = next(s for s in session.streams if s.extent)
            context["stream"] = str(stream.id)
            details = {"connections": result["session_count"]}
        elif operation == "validation":
            project = UUID(context["project"])
            version = InterpretationStore(projects).save(project, model(), None)
            repository = ValidationStore(projects)
            corpus = repository.save_corpus(
                project,
                CorpusInput(name="Control corpus", spec={"capture_ids": [CAPTURE_ID]}),
            )
            frozen = repository.freeze(
                project,
                RunInput(
                    corpus_version_id=corpus.id, interpretation_version_id=version.id
                ),
            )
            sink = Sink()
            artifact = projects.safe_path(project, ".staging/validation.jsonl")
            validation_worker(
                sink,
                Cancellation(),
                os.environ["PROTOCOL_LAB_DATABASE_URL"],
                str(projects.root),
                frozen,
                str(artifact),
            )
            assert (
                sink.summary
                and sink.summary["message_counts"]["passed"] == expected["messages"]
            )
            (output / "snapshot.json").write_text(frozen.model_dump_json())
            context["run"] = str(frozen.id)
            details = sink.summary
        elif operation == "validation_publication":
            frozen = RunSnapshot.model_validate_json(
                (output / "snapshot.json").read_bytes()
            )
            artifact = projects.safe_path(
                frozen.project_id, ".staging/validation.jsonl"
            )
            result = ValidationStore(projects).publish(frozen, artifact, {})
            assert result["outcome"] == "validated"
            details = {"messages": expected["messages"]}
        elif operation == "reads":
            tcp = ReconstructionStore(projects)
            latencies = []
            for _ in range(20):
                before = time.perf_counter()
                data = tcp.ranges(UUID(context["stream"]), 0, 16)
                assert data.blocks and data.blocks[0].status == "known"
                assert projects.packets(CAPTURE_ID, 0, 1)
                assert ValidationStore(projects).get(UUID(context["run"]))
                latencies.append(time.perf_counter() - before)
            details = {
                "samples": 20,
                "min_seconds": min(latencies),
                "max_seconds": max(latencies),
                "p95_seconds": sorted(latencies)[18],
            }
        elif operation == "snapshot":
            bundle = snapshot(projects, UUID(context["project"]), output / "bundle")
            details = {
                "table_counts": bundle.table_counts,
                "expanded_bytes": sum(m.size_bytes for m in bundle.members.values()),
            }
        elif operation == "zip":
            pack(output / "bundle", output / "project.zip")
            details = {"archive_bytes": (output / "project.zip").stat().st_size}
        elif operation == "verify":
            verified = verify_bundle(output / "bundle")
            assert str(verified.project_id) == context["project"]
        elif operation == "restore":
            # Prevent reads of the old root. Destination uses an independently migrated schema.
            projects.root.rename(output / "old-root-unavailable")
            unpack(output / "project.zip", output / "unpacked")
            destination_engine = make_engine(
                os.environ["PROTOCOL_LAB_BENCHMARK_RESTORE_URL"]
            )
            try:
                destination = ProjectStore(destination_engine, output / "destination")
                restored = restore(destination, output / "unpacked")
                assert restored["outcome"] == "restored"
                assert destination.get_capture(CAPTURE_ID).sha256 == expected["sha256"]
                run = ValidationStore(destination).get(UUID(context["run"]))
                assert run.coverage.message_counts["passed"] == expected["messages"]
                assert (
                    ReconstructionStore(destination)
                    .ranges(UUID(context["stream"]), 0, 16)
                    .blocks
                )
                details = {
                    "messages": run.coverage.message_counts["passed"],
                    "original_root_unavailable": True,
                }
            finally:
                destination_engine.dispose()
        context_path.write_text(json.dumps(context))
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {
            "operation": operation,
            "seconds": round(time.perf_counter() - start, 3),
            "peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
            **details,
        }
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker", choices=OPERATIONS)
    args = parser.parse_args()
    args.workload = args.workload.resolve()
    args.output = args.output.resolve()
    if args.worker:
        print(json.dumps(worker(args.worker, args.workload, args.output)))
        return
    database = os.environ.get("PROTOCOL_LAB_TEST_DATABASE_URL")
    if not database or make_url(database).host not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit(
            "Set PROTOCOL_LAB_TEST_DATABASE_URL to an explicit localhost test DB"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    admin = create_engine(database)
    schemas = ["pl_bench_" + uuid4().hex for _ in range(2)]
    report = {
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "scope": "PostgreSQL/application publication and portability; separate from core Linux profile",
        "measurements": [],
    }
    try:
        urls = []
        for schema in schemas:
            with admin.begin() as conn:
                conn.execute(text(f'CREATE SCHEMA "{schema}"'))
            urls.append(
                make_url(database)
                .update_query_dict({"options": f"-csearch_path={schema}"})
                .render_as_string(hide_password=False)
            )
            subprocess.run(
                [str(ROOT / "backend/.venv/bin/alembic"), "upgrade", "head"],
                cwd=ROOT / "backend",
                env={**os.environ, "PROTOCOL_LAB_DATABASE_URL": urls[-1]},
                check=True,
            )
        for operation in OPERATIONS:
            completed = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--worker",
                    operation,
                    "--workload",
                    str(args.workload),
                    "--output",
                    str(args.output),
                ],
                text=True,
                capture_output=True,
                check=False,
                env={
                    **os.environ,
                    "PROTOCOL_LAB_DATABASE_URL": urls[0],
                    "PROTOCOL_LAB_BENCHMARK_RESTORE_URL": urls[1],
                },
            )
            if completed.returncode:
                report["failure"] = {
                    "operation": operation,
                    "stderr": completed.stderr[-4000:],
                }
                raise ValueError(completed.stderr)
            value = json.loads(completed.stdout)
            report["measurements"].append(value)
            print(json.dumps(value), flush=True)
            (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))
    finally:
        (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))
        for schema in schemas:
            with admin.begin() as conn:
                conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        admin.dispose()


if __name__ == "__main__":
    main()
