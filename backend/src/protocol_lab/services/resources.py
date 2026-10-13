"""Shared protective output limits, independent of HTTP and persistence."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ResultLimits:
    max_results: int = 500_000
    max_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        if self.max_results < 1 or self.max_bytes < 1:
            raise ValueError("Result limits must be positive")


class ResultBudget:
    def __init__(self, limits: ResultLimits):
        self.limits = limits
        self.rows = self.size = 0

    def consume(self, line: str):
        self.rows += 1
        self.size += len(line.encode("utf-8"))
        if self.rows > self.limits.max_results or self.size > self.limits.max_bytes:
            raise ValueError(
                f"Result exceeds configured limits: rows {self.rows}/{self.limits.max_results}, "
                f"bytes {self.size}/{self.limits.max_bytes}; no completed result published"
            )
