"""Bounded CSV/JSON action-log parsing; timestamps remain exact nanoseconds."""

import csv
import io
import json
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Literal
from uuid import UUID, uuid5

from pydantic import Field

from protocol_lab.domain.models import Record

MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_ROWS = 100000


class LogError(ValueError):
    pass


class LogMapping(Record):
    timestamp_field: str = Field(min_length=1, max_length=200)
    label_field: str = Field(min_length=1, max_length=200)
    parameters_field: str | None = Field(default=None, max_length=200)
    timestamp_format: Literal["iso8601", "unix_s", "unix_ms", "unix_ns"] = "iso8601"
    delimiter: Literal[",", ";", "\t"] = ","


class ActionEvent(Record):
    id: UUID
    log_id: UUID
    row_index: int
    timestamp_ns: str
    label: str = Field(min_length=1, max_length=500)
    parameters_json: str = Field(max_length=10000)


class LogDiagnostic(Record):
    row_index: int
    code: str


def timestamp_ns(value, format):
    text = str(value).strip()
    if format == "iso8601":
        match = re.fullmatch(
            r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", text
        )
        if not match:
            raise ValueError("ISO timestamp requires timezone and at most 9 fractional digits")
        date = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
        delta = date.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
        result = (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or "").ljust(9, "0"))
    else:
        if len(text) > 80:
            raise ValueError("Timestamp too long")
        number = Decimal(text)
        if not number.is_finite() or number.adjusted() > 25:
            raise ValueError("Timestamp out of range")
        sign, digits, exponent = number.as_tuple()
        # Shift the decimal exponent exactly, independently of the Decimal context.
        scaled = Decimal(
            (sign, digits, exponent + {"unix_s": 9, "unix_ms": 6, "unix_ns": 0}[format])
        )
        if scaled != scaled.to_integral_value():
            raise ValueError("Timestamp precision exceeds nanoseconds")
        result = int(scaled)
    if abs(result) > 2**63 - 1:
        raise ValueError("Timestamp out of range")
    return str(result)


def parameters_json(value):
    """Encode JSON numbers without changing Decimal values into quoted strings."""
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Non-finite JSON number")
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(parameters_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + parameters_json(item)
                for key, item in value.items()
            )
            + "}"
        )
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def log_rows(data: bytes, format: Literal["csv", "json"], delimiter=","):
    if len(data) > MAX_LOG_BYTES:
        raise LogError("Action log exceeds 16 MiB; no completed log published")
    try:
        content = data.decode("utf-8-sig")
        if format == "json":

            def reject_constant(value):
                raise LogError("JSON action log contains a non-finite number")

            rows = json.loads(content, parse_float=Decimal, parse_constant=reject_constant)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise LogError("JSON action log must be an array of flat objects")
            fields = list(dict.fromkeys(key for row in rows for key in row))
        else:
            reader = csv.DictReader(io.StringIO(content), delimiter=delimiter, strict=True)
            fields = reader.fieldnames or []
            if len(fields) != len(set(fields)):
                raise LogError("CSV header contains duplicate fields")
            rows = list(reader)
        if not fields or len(fields) > 128 or len(rows) > MAX_ROWS:
            raise LogError("Action log has no fields or exceeds field/row limits")
        if any(not isinstance(key, str) or len(key) > 200 for key in fields):
            raise LogError("Action log field names are invalid")
        return fields, rows
    except (UnicodeError, json.JSONDecodeError, csv.Error, RecursionError) as exc:
        raise LogError("Invalid UTF-8 CSV/JSON action log; source was not modified") from exc


def parse_events(log_id, data, format, mapping, cancelled=lambda: False):
    from protocol_lab.capture.index import WorkCancelled

    fields, rows = log_rows(data, format, mapping.delimiter)
    required = [mapping.timestamp_field, mapping.label_field]
    if mapping.parameters_field:
        required.append(mapping.parameters_field)
    if any(name not in fields for name in required):
        raise LogError("Mapped field is absent from action log")
    events, diagnostics = [], []
    rejected = 0
    for index, row in enumerate(rows, 1):
        if cancelled():
            raise WorkCancelled
        try:
            label = row[mapping.label_field]
            if not isinstance(label, str):
                raise ValueError("label")
            if None in row:  # Extra CSV columns have no unambiguous header mapping.
                raise ValueError("columns")
            event = ActionEvent(
                id=uuid5(log_id, str(index)),
                log_id=log_id,
                row_index=index,
                timestamp_ns=timestamp_ns(row[mapping.timestamp_field], mapping.timestamp_format),
                label=label,
                parameters_json=parameters_json(
                    row.get(mapping.parameters_field) if mapping.parameters_field else {}
                ),
            )
            events.append(event)
        except (ValueError, TypeError, KeyError, InvalidOperation, RecursionError):
            rejected += 1
            if len(diagnostics) < 100:
                diagnostics.append(LogDiagnostic(row_index=index, code="invalid_mapped_row"))
    return events, {
        "row_count": len(rows),
        "event_count": len(events),
        "rejected_rows": rejected,
        "diagnostics": [d.model_dump() for d in diagnostics],
        "diagnostics_complete": rejected <= 100,
    }
