"""Exact supported framing drafts; analytical regions are never silently discarded."""

from protocol_lab.framing.engine import LengthRule, MarkerRule
from protocol_lab.inference.models import FramingCandidateRule
from protocol_lab.inference.results import DraftResult
from protocol_lab.interpretation.schema import ProtocolModel, canonical


def model_draft(candidate):
    if not isinstance(candidate.rule, FramingCandidateRule):
        return DraftResult(
            candidate_id=candidate.id,
            compilable=False,
            diagnostics=(
                candidate.compiler_reason
                or "A1 cannot compile this analytical rule independently.",
            ),
        )
    framing, fields, checks = candidate.rule.framing, [], []
    rule = framing.rule
    if isinstance(rule, LengthRule):
        if rule.offset:
            fields.append(dict(kind="bytes", name="header_prefix", length=rule.offset))
        fields.append(
            dict(
                kind="int", name="length_value", width=rule.width, signed=False, endian=rule.endian
            )
        )
        fields.append(dict(kind="bytes", name="body", length="remaining"))
        checks.append(
            dict(
                kind="length",
                field="body",
                expected=dict(
                    field="length_value",
                    multiplier=rule.multiplier,
                    add=rule.adjustment - rule.offset - rule.width,
                ),
            )
        )
    elif isinstance(rule, MarkerRule):
        # Bytes after the start are explicitly undecoded; the paired framer checks the end.
        fields.extend(
            [
                dict(
                    kind="bytes",
                    name="start_marker",
                    length=len(rule.start_hex) // 2,
                    constant_hex=rule.start_hex,
                ),
                dict(kind="bytes", name="body_and_end_marker", length="remaining"),
            ]
        )
    else:
        fields.append(dict(kind="bytes", name="undecoded_message", length=rule.size))
    model = ProtocolModel.model_validate(
        dict(
            schema_version="interpretation-1",
            name="Candidate framing draft",
            framing=framing.model_dump(),
            fields=fields,
            checks=checks,
        )
    )
    return DraftResult(
        candidate_id=candidate.id,
        compilable=True,
        document_json=canonical(model),
        diagnostics=(
            "Exact framing transferred; payload meaning is unspecified. "
            "Save a new model version and validate the complete corpus.",
        ),
    )
