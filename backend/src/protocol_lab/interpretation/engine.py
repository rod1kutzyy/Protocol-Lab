"""Construct-backed field decoding, independent of HTTP and database adapters."""

import io
from bisect import bisect_right
from typing import Literal

from construct import (
    Array,
    Bytes,
    BytesInteger,
    Construct,
    ConstructError,
    Struct,
    Subconstruct,
    Switch,
)

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.diagnostics import TechnicalLimit, technical_limit
from protocol_lab.domain.models import ByteRange, Record, StreamRange
from protocol_lab.framing.engine import CHUNK, Piece, StreamInput
from protocol_lab.interpretation.checksums import REGISTRY, calculate, covered_bytes
from protocol_lab.interpretation.corpus_schema import ChecksumCheck
from protocol_lab.interpretation.schema import (
    ArrayField,
    BytesField,
    DelimitedBytesField,
    IntField,
    Remaining,
    SwitchField,
)

VERSION = "interpretation-v4"


class DecodedField(Record):
    path: str
    kind: Literal["int", "bytes", "delimited_bytes", "array", "switch"]
    value: str  # Integer decimal strings preserve 64-bit values in browsers/JSON.
    anchor: StreamRange | None = None  # Empty fields have no nonempty source range.
    offset: int
    length: int
    preview_truncated: bool = False


class UnknownRange(Record):
    anchor: StreamRange
    reason: str


class MessageResult(Record):
    piece_id: str
    anchor: StreamRange
    status: Literal["passed", "failed", "unknown", "ambiguous", "not_applicable"]
    diagnostic: str
    fields: tuple[DecodedField, ...]
    unknown_ranges: tuple[UnknownRange, ...]
    technical_limit: TechnicalLimit | None = None


class Problem(Exception):
    def __init__(self, code, limit=None):
        self.code = code
        self.limit = limit


def problem_status(problem):
    return (
        "unknown"
        if problem.limit is not None
        or problem.code
        in {
            "unconfigured_variant",
            "field_has_unavailable_or_ambiguous_bytes",
            "checksum_field_unavailable",
        }
        else "failed"
    )


class Input(io.RawIOBase):
    def __init__(self, source, start, end, cancelled):
        self.source, self.start, self.end, self.cancelled = source, start, end, cancelled
        self.position = 0
        self.error = None

    def tell(self):
        return self.position

    def read(self, length=-1):
        try:
            return self._read(length)
        except (Problem, WorkCancelled) as exc:
            self.error = exc
            raise

    def _read(self, length):
        if self.cancelled():
            raise WorkCancelled
        if length < 0 or length > self.end - self.start - self.position:
            raise Problem("field_exceeds_message")
        left = self.start + self.position
        if self.source.status(left, left + length) != "known":
            raise Problem("field_has_unavailable_or_ambiguous_bytes")
        chunks = []
        for offset in range(0, length, CHUNK):
            if self.cancelled():
                raise WorkCancelled
            chunks.append(self.source.read(left + offset, min(CHUNK, length - offset)))
        self.position += length
        return b"".join(chunks)


def amount(expr, context, maximum, limit_name="max_message_bytes"):
    value = expr if isinstance(expr, int) else context[expr.field] * expr.multiplier + expr.add
    if value < 0:
        raise Problem("negative_computed_length_or_count")
    if value > maximum:
        raise Problem(f"{limit_name}_exceeded", technical_limit(limit_name, value, maximum))
    return value


class UnknownVariant(Construct):
    def _parse(self, stream, context, path):
        raise Problem("unconfigured_variant")


class Delimited(Construct):
    """Read through one explicitly configured terminator under a hard byte cap."""

    def __init__(self, field):
        super().__init__()
        self.field = field
        self.terminator = bytes.fromhex(field.terminator_hex)

    def _parse(self, stream, context, path):
        value = bytearray()
        while len(value) < self.field.max_length:
            chunk = stream.read(1)
            value.extend(chunk)
            if value.endswith(self.terminator):
                return bytes(
                    value if self.field.include_terminator else value[: -len(self.terminator)]
                )
        raise Problem(
            "max_delimited_length_exceeded",
            technical_limit("max_delimited_field_bytes", len(value) + 1, self.field.max_length),
        )


class Item(Subconstruct):
    def _parse(self, stream, context, path):
        tracker = context._params.tracker
        tracker["path"].append(f"[{context._index}]")
        try:
            return self.subcon._parsereport(stream, context, path)
        finally:
            tracker["path"].pop()


class Traced(Subconstruct):
    def __init__(self, field, subcon):
        super().__init__(subcon)
        self.field = field

    def _parse(self, stream, context, path):
        tracker = context._params.tracker
        if tracker["cancelled"]():
            raise WorkCancelled
        tracker["count"] += 1
        if tracker["count"] > tracker["limit"]:
            raise Problem(
                "max_decoded_fields_exceeded",
                technical_limit("max_decoded_fields", tracker["count"], tracker["limit"]),
            )
        field = self.field
        start = stream.tell()
        tracker["path"].append(field.name)
        label = ".".join(tracker["path"]).replace(".[", "[")
        try:
            value = self.subcon._parsereport(stream, context, path)
            end = stream.tell()
            anchor = tracker["anchor"]
            absolute = anchor.byte_range.start + start
            source_anchor = (
                anchor.model_copy(
                    update={"byte_range": ByteRange(start=absolute, end=absolute + end - start)}
                )
                if end > start
                else None
            )
            rendered = (
                str(value)
                if isinstance(field, IntField)
                else (
                    value[:64].hex()
                    if isinstance(field, (BytesField, DelimitedBytesField))
                    else (
                        str(len(value))
                        if isinstance(field, ArrayField)
                        else str(context[field.selector])
                    )
                )
            )
            tracker["fields"].append(
                DecodedField(
                    path=label,
                    kind=field.kind,
                    value=rendered,
                    anchor=source_anchor,
                    offset=absolute,
                    length=end - start,
                    preview_truncated=isinstance(field, (BytesField, DelimitedBytesField))
                    and len(value) > 64,
                )
            )
            tracker["consumed"] = max(tracker["consumed"], end)
            if isinstance(field, IntField):
                if field.constant is not None and value != field.constant:
                    raise Problem(f"{label}:constant_check_failed")
                if (field.minimum is not None and value < field.minimum) or (
                    field.maximum is not None and value > field.maximum
                ):
                    raise Problem(f"{label}:range_check_failed")
            if (
                isinstance(field, BytesField)
                and field.constant_hex is not None
                and value != bytes.fromhex(field.constant_hex)
            ):
                raise Problem(f"{label}:constant_check_failed")
            return value
        finally:
            tracker["path"].pop()


def compile_model(model):
    """Compile only our closed declarative language; no evaluation of imported code."""

    def structure(fields):
        compiled = []
        for field in fields:
            if isinstance(field, IntField):
                subcon = BytesInteger(
                    field.width, signed=field.signed, swapped=field.endian == "little"
                )
            elif isinstance(field, BytesField):

                def length(ctx, expr=field.length):
                    stream = ctx._io
                    if isinstance(expr, Remaining):
                        count = stream.end - stream.start - stream.tell() - expr.remaining_minus
                        if count < 0:
                            raise Problem("negative_remaining_length")
                        return count
                    return (
                        stream.end - stream.start - stream.tell()
                        if expr == "remaining"
                        else amount(expr, ctx, model.framing.max_message_bytes)
                    )

                subcon = Bytes(length)
            elif isinstance(field, DelimitedBytesField):
                subcon = Delimited(field)
            elif isinstance(field, ArrayField):
                subcon = Array(
                    lambda ctx, expr=field.count: amount(
                        expr, ctx, model.max_array_items, "max_array_items"
                    ),
                    Item(structure(field.fields)),
                )
            else:
                subcon = Switch(
                    lambda ctx, ref=field.selector: ctx[ref],
                    {int(k): structure(v) for k, v in field.cases.items()},
                    default=UnknownVariant(),
                )
            compiled.append(field.name / Traced(field, subcon))
        return Struct(*compiled)

    return structure(model.fields)


def parse_message(model, parser, piece: Piece, source: StreamInput, cancelled=lambda: False,
                  direction=None):
    anchor, interval = piece.anchor, piece.anchor.byte_range
    fields, unknown = [], []
    tracker = dict(
        fields=fields,
        path=[],
        anchor=anchor,
        consumed=0,
        count=0,
        limit=model.max_decoded_fields,
        cancelled=cancelled,
    )
    length = interval.end - interval.start
    position, diagnostic = 0, "rules_executed"
    limit = piece.technical_limit
    if model.direction != "both" and direction is None:
        status, diagnostic = "unknown", "model_direction_prerequisite_unavailable"
    elif model.direction not in {"both", direction}:
        status, diagnostic = "not_applicable", "outside_model_direction_scope"
    elif piece.kind != "message":
        status, diagnostic = "not_applicable", "unframed_data"
    elif length > model.framing.max_message_bytes:
        status, diagnostic = "unknown", "max_message_bytes_exceeded"
        limit = technical_limit("max_message_bytes", length, model.framing.max_message_bytes)
    else:
        stream = Input(source, interval.start, interval.end, cancelled)
        try:
            values = parser.parse_stream(stream, tracker=tracker)
            checksum_bytes = 0
            for check in model.checks:
                if isinstance(check, ChecksumCheck):
                    field = next((f for f in fields if f.path == check.field), None)
                    if field is None:
                        raise Problem("checksum_field_unavailable")
                    if field.length != REGISTRY[check.algorithm].width // 8:
                        raise Problem(f"{check.field}:checksum_field_width_mismatch")
                    checksum_bytes += length
                    if checksum_bytes > model.max_checksum_bytes:
                        raise Problem(
                            "max_checksum_bytes_exceeded",
                            technical_limit(
                                "max_checksum_bytes", checksum_bytes, model.max_checksum_bytes
                            ),
                        )
                    reader = Input(source, interval.start, interval.end, cancelled)
                    raw = reader.read(length)
                    start = field.offset - interval.start
                    end = start + field.length
                    try:
                        covered = covered_bytes(
                            raw,
                            start,
                            end,
                            check.coverage,
                            check.covered_ranges,
                            check.exclude_field,
                            check.coverage_start,
                        )
                    except ValueError:
                        raise Problem("checksum_coverage_outside_message") from None
                    expected = calculate(check.algorithm, covered, cancelled)
                    actual = int.from_bytes(raw[start:end], check.byte_order)
                    if actual != expected:
                        raise Problem(
                            f"{check.field}:checksum_check_failed:"
                            f"{check.algorithm}:expected={expected}:observed={actual}"
                        )
                    continue
                field = next(f for f in model.fields if f.name == check.field)
                actual = (
                    len(values[check.field])
                    if not isinstance(field, SwitchField)
                    else next(f.length for f in fields if f.path == check.field)
                )
                if actual != amount(check.expected, values, model.framing.max_message_bytes):
                    raise Problem(f"{check.field}:length_check_failed")
            position = stream.tell()
            status = "passed" if position == length else "unknown"
            if position < length:
                diagnostic = "uninterpreted_tail"
        except Problem as exc:
            diagnostic = exc.code
            position = tracker["consumed"]
            status, limit = problem_status(exc), exc.limit
        except ConstructError:
            if isinstance(stream.error, WorkCancelled):
                raise stream.error from None
            problem = (
                stream.error
                if isinstance(stream.error, Problem)
                else Problem("construct_parse_failed")
            )
            diagnostic = problem.code
            position = tracker["consumed"]
            status, limit = problem_status(problem), problem.limit
        # Data uncertainty takes precedence over claiming a complete rule success.
        data_status = source.status(interval.start, interval.end)
        if data_status in {"ambiguous", "mixed"}:
            status = "ambiguous"
        elif data_status == "incomplete":
            status = "unknown"
    # The undecoded suffix remains partitioned by source status; never manufacture bytes.
    left = interval.start + position
    index = bisect_right(source.ends, left)
    while index < len(source.ranges):
        if cancelled():
            raise WorkCancelled
        a, b, data_status = source.ranges[index]
        if a >= interval.end:
            break
        start, end = max(left, a), min(interval.end, b)
        if end > start:
            reason = "uninterpreted" if data_status == "known" else data_status
            if (
                unknown
                and unknown[-1].reason == reason
                and unknown[-1].anchor.byte_range.end == start
            ):
                old = unknown.pop()
                start = old.anchor.byte_range.start
            if len(unknown) >= model.max_decoded_fields:
                raise ValueError(
                    "Unknown range count exceeds max_decoded_fields; no result published"
                )
            unknown.append(
                UnknownRange(
                    anchor=anchor.model_copy(
                        update={"byte_range": ByteRange(start=start, end=end)}
                    ),
                    reason=reason,
                )
            )
        index += 1
    if model.corpus_checks:
        diagnostic += ";corpus_checks_execute_in_corpus_validation"
    return MessageResult(
        piece_id=str(piece.id),
        anchor=anchor,
        status=status,
        diagnostic=diagnostic,
        fields=tuple(fields),
        unknown_ranges=tuple(unknown),
        technical_limit=limit,
    )
