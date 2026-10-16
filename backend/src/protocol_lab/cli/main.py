"""Documented local adapters. apply needs no PostgreSQL and never overwrites output."""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from protocol_lab.capture.index import IndexSettings
from protocol_lab.interpretation.document import load_model
from protocol_lab.services.application import apply_capture
from protocol_lab.services.settings import Settings
from protocol_lab.storage.database import make_engine
from protocol_lab.storage.portable import pack, restore, snapshot, unpack, verify_bundle
from protocol_lab.storage.projects import ProjectStore


def atomic_output(path, writer, mode="w"):
    path = path.resolve()
    if path.exists():
        raise ValueError("Output already exists; refusing overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".protocol-lab-", dir=path.parent)
    try:
        with os.fdopen(fd, mode, **({"encoding": "utf-8"} if "b" not in mode else {})) as output:
            result = writer(output)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)  # exclusive publication, even if another writer races
        return result
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="protocol-lab", description="Offline TCP/IPv4 research")
    commands = parser.add_subparsers(dest="command", required=True)
    apply = commands.add_parser(
        "apply", help="Apply JSON interpretation to PCAP/PCAPNG without a DB"
    )
    apply.add_argument("--model", type=Path, required=True)
    apply.add_argument("--capture", type=Path, required=True)
    apply.add_argument("--output", type=Path, required=True)
    apply.add_argument("--checksum-policy", choices=["warn", "ignore", "reject"], default="warn")
    apply.add_argument("--action-log", type=Path, action="append", default=[])
    apply.add_argument("--log-mapping", type=Path)
    apply.add_argument("--clock-offset-ns", type=int, default=0)
    for name in ("infer", "evaluate-candidate"):
        command = commands.add_parser(
            name, help="Offline automatic analysis with the shared A4 engine"
        )
        command.add_argument("--capture", type=Path, action="append", required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--spec", type=Path, required=name == "infer")
        command.add_argument("--holdout", type=Path, action="append", default=[])
        if name == "evaluate-candidate":
            command.add_argument("--candidate", type=Path, required=True)
    project = commands.add_parser(
        "project", help="Save, verify, export or restore a portable project"
    )
    operations = project.add_subparsers(dest="operation", required=True)
    for name in ["save", "export"]:
        command = operations.add_parser(name)
        command.add_argument("--project-id", type=UUID, required=True)
        command.add_argument("--output", type=Path, required=True)
    verify = operations.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    recovery = operations.add_parser("restore")
    source = recovery.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--directory", type=Path)
    args = parser.parse_args(argv)
    engine = None
    try:
        if args.command in {"infer", "evaluate-candidate"}:
            from protocol_lab.inference.document import MAX_DOCUMENT_BYTES
            from protocol_lab.services.inference_files import infer_files

            for path in [args.spec, getattr(args, "candidate", None)]:
                if path and path.stat().st_size > MAX_DOCUMENT_BYTES:
                    raise ValueError("Inference input document exceeds 512 KiB")
            settings = Settings.environment()
            if (
                sum(path.stat().st_size for path in [*args.capture, *args.holdout])
                > settings.max_upload_bytes
            ):
                raise ValueError("Inference captures exceed configured combined input limit")
            result = atomic_output(
                args.output,
                lambda output: infer_files(
                    args.capture,
                    args.spec.read_text(encoding="utf-8") if args.spec else None,
                    output,
                    args.holdout,
                    args.candidate.read_text(encoding="utf-8")
                    if args.command == "evaluate-candidate"
                    else None,
                    IndexSettings(
                        max_packets=settings.max_packets, max_block_bytes=settings.max_block_bytes
                    ),
                ),
            )
            print(json.dumps({"output": str(args.output), "kind": result.__class__.__name__}))
            return 0
        if args.command == "apply":
            if args.model.stat().st_size > 1024 * 1024:
                raise ValueError("Model exceeds 1 MiB")
            model = load_model(args.model.read_text(encoding="utf-8"))
            settings = Settings.environment()
            if args.capture.stat().st_size > settings.max_upload_bytes:
                raise ValueError("Capture exceeds configured input limit")
            from uuid import NAMESPACE_URL, uuid5

            from protocol_lab.capture.index import sha256_file
            from protocol_lab.research.action_logs import MAX_LOG_BYTES, LogMapping, parse_events

            events, logs = [], []
            if bool(args.action_log) != bool(args.log_mapping):
                raise ValueError("--action-log requires --log-mapping and vice versa")
            if args.log_mapping and args.log_mapping.stat().st_size > 65536:
                raise ValueError("Log mapping exceeds 64 KiB")
            mapping = (
                LogMapping.model_validate_json(args.log_mapping.read_text(encoding="utf-8"))
                if args.log_mapping
                else None
            )
            for log_path in args.action_log:
                if log_path.stat().st_size > MAX_LOG_BYTES:
                    raise ValueError("Action log exceeds 16 MiB")
                checksum = sha256_file(log_path)
                log_id = uuid5(NAMESPACE_URL, f"protocol-lab:log:{checksum}")
                parsed, summary = parse_events(
                    log_id, log_path.read_bytes(), log_path.suffix.lstrip("."), mapping
                )
                if summary["rejected_rows"]:
                    raise ValueError("Action log contains invalid rows; correct its mapping")
                events.extend(
                    event.model_copy(
                        update={"timestamp_ns": str(int(event.timestamp_ns) + args.clock_offset_ns)}
                    )
                    for event in parsed
                )
                logs.append(
                    dict(
                        id=str(log_id),
                        sha256=checksum,
                        relative_path=log_path.name,
                        mapping=mapping.model_dump(),
                        clock_offset_ns=str(args.clock_offset_ns),
                        clock_revision=1,
                    )
                )

            def apply_with_logs(output):
                result = apply_capture(
                    model,
                    args.capture,
                    output,
                    IndexSettings(
                        checksum_policy=args.checksum_policy,
                        max_packets=settings.max_packets,
                        max_block_bytes=settings.max_block_bytes,
                    ),
                    limits=settings.validation_limits,
                    action_events=tuple(events),
                    action_logs=tuple(logs),
                )
                if any(
                    sha256_file(path) != log["sha256"]
                    for path, log in zip(args.action_log, logs, strict=True)
                ):
                    raise ValueError("Action log changed during validation")
                return result

            counts = atomic_output(
                args.output,
                apply_with_logs,
            )
            print(json.dumps({"output": str(args.output), "message_counts": counts.message_counts}))
            # A completed validation with counterexamples is still a successful command.
            return 0
        if args.operation == "verify":
            bundle = verify_bundle(args.directory.resolve())
            print(json.dumps({"outcome": "verified", "project_id": str(bundle.project_id)}))
            return 0
        settings = Settings.environment()
        if not settings.database_url:
            raise ValueError("Set PROTOCOL_LAB_DATABASE_URL and run alembic upgrade head")
        engine = make_engine(settings.database_url)
        projects = ProjectStore(engine, settings.project_root)
        with tempfile.TemporaryDirectory(prefix="protocol-lab-") as temporary:
            directory = Path(temporary) / "bundle"
            if args.operation == "restore":
                if args.archive:
                    if args.archive.stat().st_size > settings.max_archive_bytes:
                        raise ValueError("Archive exceeds configured upload limit")
                    unpack(args.archive, directory)
                else:
                    shutil.copytree(args.directory.resolve(), directory, symlinks=True)
                print(json.dumps(restore(projects, directory)))
            else:
                if args.output.exists():
                    raise ValueError("Output already exists; refusing overwrite")
                snapshot(projects, args.project_id, directory)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                if args.operation == "save":
                    # Publish on the destination filesystem; no existing directory is replaced.
                    args.output.mkdir()
                    try:
                        shutil.copytree(directory, args.output, dirs_exist_ok=True)
                    except BaseException:
                        shutil.rmtree(args.output)
                        raise
                else:
                    archive = Path(temporary) / "project.zip"
                    pack(directory, archive)
                    with archive.open("rb") as source:
                        atomic_output(
                            args.output,
                            lambda output: shutil.copyfileobj(source, output),
                            mode="wb",
                        )
                print(json.dumps({"outcome": args.operation, "output": str(args.output)}))
        return 0
    except (OSError, ValueError) as exc:
        print(f"protocol-lab: {exc}", file=sys.stderr)
        return 2
    except SQLAlchemyError:
        print(
            "protocol-lab: PostgreSQL unavailable, identity conflict or migrations missing; "
            "existing research unchanged",
            file=sys.stderr,
        )
        return 2
    finally:
        if engine:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
