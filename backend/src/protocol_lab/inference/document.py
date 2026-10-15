"""Bounded strict JSON loading, shared by future GUI/CLI adapters."""

import json
import math

from pydantic import TypeAdapter

from protocol_lab.inference.models import SCHEMAS

MAX_DOCUMENT_BYTES = 512 * 1024


def load_document(document: str, schema="spec"):
    if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("Inference JSON exceeds 512 KiB document limit")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON property {key!r}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant {value}")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    try:
        json.loads(
            document,
            object_pairs_hook=unique,
            parse_constant=invalid_constant,
            parse_float=finite_float,
        )
        return TypeAdapter(SCHEMAS[schema]).validate_json(document)
    except RecursionError as exc:
        raise ValueError("Inference JSON exceeds supported nesting") from exc
