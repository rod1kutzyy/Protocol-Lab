import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

from protocol_lab.services.resources import ResultLimits

PROJECT_DIRECTORY = Path(__file__).resolve().parents[4]


@dataclass(frozen=True)
class Settings:
    database_url: str | None = None
    project_root: Path = Path("projects")
    max_upload_bytes: int = 128 * 1024 * 1024
    max_block_bytes: int = 16 * 1024 * 1024
    max_packets: int = 1_000_000
    max_archive_bytes: int = 512 * 1024 * 1024
    max_workers: int = 2
    max_jobs: int = 128
    max_validation_results: int = 500_000
    max_validation_bytes: int = 512 * 1024 * 1024
    max_interpretation_bytes: int = 256 * 1024 * 1024

    def __post_init__(self):
        for name, value in vars(self).items():
            if name.startswith("max_") and (type(value) is not int or value < 1):
                raise ValueError(f"{name} must be a positive integer")
        if self.max_block_bytes < 1024:
            raise ValueError("max_block_bytes must be at least 1024")

    @property
    def validation_limits(self):
        return ResultLimits(self.max_validation_results, self.max_validation_bytes)

    @classmethod
    def environment(cls, env_file: Path = PROJECT_DIRECTORY / ".env"):
        # Read a fixed location, independent of the shell's working directory.
        # Do not mutate os.environ or override explicitly exported settings.
        values = {
            key: value
            for key, value in dotenv_values(env_file, interpolate=False).items()
            if value is not None
        }
        values.update(os.environ)
        project_root = Path(values.get("PROTOCOL_LAB_PROJECT_ROOT", "projects"))
        if not project_root.is_absolute():
            project_root = env_file.parent / project_root
        return cls(
            database_url=values.get("PROTOCOL_LAB_DATABASE_URL"),
            project_root=project_root,
            max_upload_bytes=int(values.get("PROTOCOL_LAB_MAX_UPLOAD_BYTES", 128 * 1024 * 1024)),
            max_block_bytes=int(values.get("PROTOCOL_LAB_MAX_BLOCK_BYTES", 16 * 1024 * 1024)),
            max_archive_bytes=int(values.get("PROTOCOL_LAB_MAX_ARCHIVE_BYTES", 512 * 1024 * 1024)),
            max_packets=int(values.get("PROTOCOL_LAB_MAX_PACKETS", 1_000_000)),
            max_workers=int(values.get("PROTOCOL_LAB_MAX_WORKERS", 2)),
            max_jobs=int(values.get("PROTOCOL_LAB_MAX_JOBS", 128)),
            max_validation_results=int(values.get("PROTOCOL_LAB_MAX_VALIDATION_RESULTS", 500_000)),
            max_validation_bytes=int(
                values.get("PROTOCOL_LAB_MAX_VALIDATION_BYTES", 512 * 1024 * 1024)
            ),
            max_interpretation_bytes=int(
                values.get("PROTOCOL_LAB_MAX_INTERPRETATION_BYTES", 256 * 1024 * 1024)
            ),
        )
