"""Bounded, deterministic message framing independent of HTTP and persistence."""

import hashlib
import json
from bisect import bisect_right
from collections import Counter
from collections.abc import Callable
from typing import Annotated, Literal
from uuid import UUID, uuid5

from pydantic import Field, model_validator

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import ByteRange, Record, StreamRange

VERSION = "framing-v1"
CHUNK = 65536


class ManualRule(Record):
    kind: Literal["manual"]
    ranges: tuple[ByteRange, ...] = Field(default=(), max_length=10000)

    @model_validator(mode="after")
    def ordered(self):
        previous = 0
        for interval in self.ranges:
            if interval.end <= interval.start or interval.start < previous:
                raise ValueError("Manual ranges must be nonempty, ordered and nonoverlapping")
            previous = interval.end
        return self


class FixedRule(Record):
    kind: Literal["fixed"]
    size: int = Field(ge=1, le=16 * 1024 * 1024)


class LengthRule(Record):
    kind: Literal["length"]
    offset: int = Field(default=0, ge=0, le=65536)
    width: Literal[1, 2, 4, 8] = 2
    endian: Literal["big", "little"] = "big"
    multiplier: int = Field(default=1, ge=1, le=65536)
    adjustment: int = Field(default=0, ge=-16777216, le=16777216)


class MarkerRule(Record):
    kind: Literal["markers"]
    start_hex: str = Field(min_length=2, max_length=128, pattern=r"^(?:[a-fA-F0-9]{2})+$")
    end_hex: str = Field(min_length=2, max_length=128, pattern=r"^(?:[a-fA-F0-9]{2})+$")


Rule = Annotated[ManualRule | FixedRule | LengthRule | MarkerRule, Field(discriminator="kind")]


class FramingSpec(Record):
    schema_version: Literal["framing-1"] = "framing-1"
    start: int = Field(default=0, ge=0)
    rule: Rule
    max_message_bytes: int = Field(default=1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_pieces: int = Field(default=200000, ge=1, le=200000)

    @model_validator(mode="after")
    def limits(self):
        if isinstance(self.rule, FixedRule) and self.rule.size > self.max_message_bytes:
            raise ValueError("Fixed size exceeds max_message_bytes")
        if isinstance(self.rule, ManualRule):
            if self.start != 0:
                raise ValueError("Manual mode uses absolute ranges; start must be zero")
            if any(r.end - r.start > self.max_message_bytes for r in self.rule.ranges):
                raise ValueError("Manual message exceeds max_message_bytes")
        return self


class Piece(Record):
    id: UUID
    framing_version: str
    kind: Literal["message", "leftover"]
    anchor: StreamRange
    boundary_status: Literal["known", "uncertain"]
    data_status: Literal["known", "incomplete", "ambiguous", "mixed"]
    diagnostic: str


class FramingResult(Record):
    id: UUID
    stream_id: UUID
    reconstruction_version: str
    capture_id: UUID
    capture_sha256: str
    engine_version: str = VERSION
    spec: FramingSpec
    extent: int
    message_count: int
    leftover_bytes: int
    uncertain_bytes: int
    pieces: tuple[Piece, ...]


def identity(stream_id, reconstruction_version, capture_sha256, spec):
    canonical = json.dumps(spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(
        (VERSION + reconstruction_version + capture_sha256 + canonical).encode()
    ).hexdigest()
    return uuid5(stream_id, digest)


class StreamInput:
    """Coverage metadata and a callback that reads only known bytes, in bounded chunks."""

    def __init__(self, extent: int, ranges: list[tuple[int, int, str]], read: Callable):
        self.extent, self.ranges, self.read_bytes = extent, ranges, read
        self.ends = [right for _, right, _ in ranges]
        cursor = 0
        for left, right, status in ranges:
            if (
                left != cursor
                or right <= left
                or status not in {"known", "gap", "truncated", "ambiguous"}
            ):
                raise ValueError("Framing requires complete, ordered stream coverage")
            cursor = right
        if cursor != extent:
            raise ValueError("Framing input extent mismatch")

    def status(self, start, end):
        statuses = set()
        index = bisect_right(self.ends, start)
        while index < len(self.ranges) and self.ranges[index][0] < end:
            statuses.add(self.ranges[index][2])
            index += 1
        missing = bool(statuses & {"gap", "truncated"})
        if "ambiguous" in statuses:
            return "mixed" if missing else "ambiguous"
        return "incomplete" if missing else "known"

    def read(self, start, length):
        if start < 0 or start + length > self.extent or length > CHUNK:
            raise ValueError("Framing read outside bounded stream range")
        if self.status(start, start + length) != "known":
            return None
        data = self.read_bytes(start, length)
        if len(data) != length:
            raise ValueError("Framing source bytes unavailable")
        return data

    def known_runs(self, start):
        left = right = None
        for a, b, status in self.ranges:
            if b <= start:
                continue
            if status == "known":
                if left is None:
                    left = max(a, start)
                right = b
            elif left is not None:
                yield left, right
                left = right = None
        if left is not None:
            yield left, right


def frame(
    stream_id,
    reconstruction_version,
    capture_id,
    capture_sha256,
    source,
    spec,
    cancelled=lambda: False,
    progress=lambda done, total: None,
):
    if spec.start > source.extent:
        raise ValueError("Framing start exceeds stream extent")
    if isinstance(spec.rule, ManualRule) and any(r.end > source.extent for r in spec.rule.ranges):
        raise ValueError("Manual range exceeds stream extent")
    run_id = identity(stream_id, reconstruction_version, capture_sha256, spec)
    pieces = []

    def check(position):
        if cancelled():
            raise WorkCancelled
        progress(position, source.extent)

    def append(left, right, kind, diagnostic=""):
        if right <= left:
            return
        check(left)
        if len(pieces) >= spec.max_pieces:
            raise ValueError("max_pieces exceeded; no complete framing result published")
        pieces.append(
            Piece(
                id=uuid5(run_id, f"{kind}:{left}:{right}"),
                framing_version=str(run_id),
                kind=kind,
                anchor=StreamRange(
                    stream_id=stream_id,
                    reconstruction_version=reconstruction_version,
                    byte_range=ByteRange(start=left, end=right),
                ),
                boundary_status="known" if kind == "message" else "uncertain",
                data_status=source.status(left, right),
                diagnostic=diagnostic,
            )
        )

    def find(pattern, left, right):
        carry = b""
        while left < right:
            check(left)
            data = source.read(left, min(CHUNK, right - left))
            combined = carry + data
            index = combined.find(pattern)
            if index >= 0:
                return left - len(carry) + index
            carry = combined[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
            left += len(data)
        return None

    cursor = spec.start
    append(0, cursor, "leftover", "before_configured_start")
    rule = spec.rule
    if isinstance(rule, ManualRule):
        for interval in rule.ranges:
            append(cursor, interval.start, "leftover", "not_manually_framed")
            append(interval.start, interval.end, "message", "manual_boundary_hypothesis")
            cursor = interval.end
        append(cursor, source.extent, "leftover", "not_manually_framed")
    elif isinstance(rule, FixedRule):
        while cursor + rule.size <= source.extent:
            append(cursor, cursor + rule.size, "message", "fixed_boundary_rule")
            cursor += rule.size
        append(cursor, source.extent, "leftover", "incomplete_fixed_message")
    elif isinstance(rule, LengthRule):
        header_end = rule.offset + rule.width
        while cursor < source.extent:
            check(cursor)
            reason = "incomplete_length_header"
            if cursor + header_end <= source.extent:
                header = source.read(cursor + rule.offset, rule.width)
                if header is None:
                    reason = "unknown_length_header_no_resynchronization"
                else:
                    total = int.from_bytes(header, rule.endian) * rule.multiplier + rule.adjustment
                    reason = "invalid_length_no_resynchronization"
                    if total >= header_end and 0 < total <= spec.max_message_bytes:
                        if cursor + total <= source.extent:
                            append(cursor, cursor + total, "message", "length_boundary_rule")
                            cursor += total
                            continue
                        reason = "incomplete_length_message"
            append(cursor, source.extent, "leftover", reason)
            break
    else:
        start_marker, end_marker = bytes.fromhex(rule.start_hex), bytes.fromhex(rule.end_hex)
        for left, right in source.known_runs(cursor):
            append(cursor, left, "leftover", "unknown_bytes_marker_barrier")
            cursor = left
            while cursor < right:
                begin = find(start_marker, cursor, right)
                if begin is None:
                    append(cursor, right, "leftover", "start_marker_not_found")
                    cursor = right
                    break
                append(cursor, begin, "leftover", "before_start_marker")
                # Limit search to a possible message size; do not scan/reject arbitrary payload.
                stop = min(right, begin + spec.max_message_bytes)
                end = find(end_marker, begin + len(start_marker), stop)
                if end is None:
                    reason = "end_marker_not_found_or_limit_exceeded"
                    append(begin, right, "leftover", reason)
                    cursor = right
                    break
                cursor = end + len(end_marker)
                append(begin, cursor, "message", "explicit_markers_included")
        append(cursor, source.extent, "leftover", "unknown_bytes_marker_barrier")
    check(source.extent)
    counts = Counter(p.kind for p in pieces)
    return FramingResult(
        id=run_id,
        stream_id=stream_id,
        reconstruction_version=reconstruction_version,
        capture_id=capture_id,
        capture_sha256=capture_sha256,
        spec=spec,
        extent=source.extent,
        message_count=counts["message"],
        leftover_bytes=sum(
            p.anchor.byte_range.end - p.anchor.byte_range.start
            for p in pieces
            if p.kind == "leftover"
        ),
        uncertain_bytes=sum(
            p.anchor.byte_range.end - p.anchor.byte_range.start
            for p in pieces
            if p.data_status != "known"
        ),
        pieces=tuple(pieces),
    )
