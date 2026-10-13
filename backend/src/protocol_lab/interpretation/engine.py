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
from protocol_lab.domain.models import ByteRange, Record, StreamRange
from protocol_lab.framing.engine import CHUNK, Piece, StreamInput
from protocol_lab.interpretation.schema import ArrayField, BytesField, IntField, SwitchField

VERSION = "interpretation-v1"


class DecodedField(Record):
    path: str
    kind: Literal["int", "bytes", "array", "switch"]
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


class Problem(Exception):
    def __init__(self, code):
        self.code = code


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


def amount(expr, context, maximum):
    value = expr if isinstance(expr, int) else context[expr.field] * expr.multiplier + expr.add
    if value < 0 or value > maximum:
        raise Problem("computed_length_or_count_outside_limit")
    return value


class UnknownVariant(Construct):
    def _parse(self, stream, context, path):
        raise Problem("unconfigured_variant")


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
            raise Problem("max_decoded_fields_exceeded")
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
                    if isinstance(field, BytesField)
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
                    preview_truncated=isinstance(field, BytesField) and len(value) > 64,
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
                    return (
                        stream.end - stream.start - stream.tell()
                        if expr == "remaining"
                        else amount(expr, ctx, model.framing.max_message_bytes)
                    )

                subcon = Bytes(length)
            elif isinstance(field, ArrayField):
                subcon = Array(
                    lambda ctx, expr=field.count: amount(expr, ctx, model.max_array_items),
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


def parse_message(model, parser, piece: Piece, source: StreamInput, cancelled=lambda: False):
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
    if piece.kind != "message":
        status, diagnostic = "not_applicable", "unframed_data"
    elif length > model.framing.max_message_bytes:
        status, diagnostic = "unknown", "max_message_bytes_exceeded"
    else:
        stream = Input(source, interval.start, interval.end, cancelled)
        try:
            values = parser.parse_stream(stream, tracker=tracker)
            for check in model.checks:
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
            status = (
                "unknown"
                if diagnostic
                in {
                    "unconfigured_variant",
                    "field_has_unavailable_or_ambiguous_bytes",
                    "max_decoded_fields_exceeded",
                }
                else "failed"
            )
        except ConstructError:
            if isinstance(stream.error, WorkCancelled):
                raise stream.error from None
            diagnostic = (
                stream.error.code if isinstance(stream.error, Problem) else "construct_parse_failed"
            )
            position = tracker["consumed"]
            status = (
                "unknown" if diagnostic == "field_has_unavailable_or_ambiguous_bytes" else "failed"
            )
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
    return MessageResult(
        piece_id=str(piece.id),
        anchor=anchor,
        status=status,
        diagnostic=diagnostic,
        fields=tuple(fields),
        unknown_ranges=tuple(unknown),
    )
