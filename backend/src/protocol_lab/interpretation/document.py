"""Shared model-document loading for HTTP, CLI and portable project inputs."""

import json

from protocol_lab.interpretation.schema import ProtocolModel


def load_model(document: str) -> ProtocolModel:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON property {key!r}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Invalid JSON constant {value}")

    try:
        json.loads(document, object_pairs_hook=unique, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError("Model JSON exceeds supported nesting") from exc
    return ProtocolModel.model_validate_json(document)
