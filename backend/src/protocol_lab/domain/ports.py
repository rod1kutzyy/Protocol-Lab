"""Core interfaces. Implementations arrive in stages 3–8; no HTTP/DB imports."""

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol

from protocol_lab.domain.models import (
    Capture,
    Corpus,
    DirectedStream,
    InterpretationVersion,
    Message,
    Packet,
    Session,
    ValidationRun,
)


class WorkContext(Protocol):
    def cancelled(self) -> bool: ...
    def progress(self, completed: int, total: int, message: str) -> None: ...


class CaptureImporter(Protocol):
    def import_capture(self, source: Path, context: WorkContext) -> Capture: ...
    def packets(self, capture: Capture) -> Iterable[Packet]: ...


class Reconstructor(Protocol):
    def reconstruct(
        self, capture: Capture, context: WorkContext
    ) -> tuple[tuple[Session, ...], tuple[DirectedStream, ...]]: ...


class Framer(Protocol):
    def frame(
        self, stream: DirectedStream, read: Callable[[int, int], bytes], settings_json: str
    ) -> Iterable[Message]: ...


class Interpreter(Protocol):
    def parse(self, message: Message, data: bytes, version: InterpretationVersion) -> str: ...


class CorpusValidator(Protocol):
    def validate(
        self, corpus: Corpus, version: InterpretationVersion, context: WorkContext
    ) -> ValidationRun: ...
