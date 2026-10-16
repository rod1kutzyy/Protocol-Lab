"""Exact supported framing drafts; analytical regions are never silently discarded."""

from protocol_lab.framing.engine import LengthRule, MarkerRule
from protocol_lab.inference.models import (
    ChecksumRule,
    CounterRule,
    FramingCandidateRule,
    TimestampRule,
)
from protocol_lab.inference.results import DraftResult
from protocol_lab.interpretation.schema import ProtocolModel, canonical


def model_draft(candidate):
    if isinstance(candidate.rule, (CounterRule, TimestampRule)) and candidate.rule.framing:
        rule = candidate.rule
        fields = []
        if rule.field.offset:
            fields.append(dict(kind="bytes", name="prefix", length=rule.field.offset))
        fields.extend(
            [
                dict(
                    kind="int",
                    name="value",
                    width=rule.field.width,
                    signed=rule.field.signed,
                    endian=rule.field.endian,
                ),
                dict(kind="bytes", name="payload", length="remaining"),
            ]
        )
        check = (
            dict(
                kind="counter",
                name="counter_relation",
                field="value",
                step=rule.step,
                increment=rule.increment,
                wrap=rule.wrap,
                payload_field="payload" if rule.step == "payload_length" else None,
            )
            if isinstance(rule, CounterRule)
            else dict(
                kind="timestamp",
                name="timestamp_relation",
                field="value",
                unit=rule.unit,
                epoch=rule.epoch,
                clock_offset_ns=rule.clock_offset_ns,
                tolerance_ns=rule.tolerance_ns,
                drift_ppm=rule.drift_ppm,
            )
        )
        model = ProtocolModel.model_validate(
            dict(
                schema_version="interpretation-2",
                name="Relational candidate draft",
                direction=candidate.scope.direction,
                framing=rule.framing,
                fields=fields,
                corpus_checks=[check],
            )
        )
        return DraftResult(
            candidate_id=candidate.id,
            compilable=True,
            document_json=canonical(model),
            diagnostics=("Exact framing and typed corpus relation transferred.",),
        )
    if isinstance(candidate.rule, ChecksumRule):
        rule = candidate.rule
        if rule.framing and rule.field_relative_to == "message_end" and rule.field.offset == 0:
            model = ProtocolModel.model_validate(
                dict(
                    schema_version="interpretation-2",
                    name="Checksum candidate draft",
                    direction=candidate.scope.direction,
                    framing=rule.framing,
                    fields=[
                        dict(
                            kind="bytes", name="body", length={"remaining_minus": rule.field.width}
                        ),
                        dict(
                            kind="int",
                            name="checksum",
                            width=rule.field.width,
                            signed=False,
                            endian=rule.field.endian,
                        ),
                    ],
                    checks=[
                        dict(
                            kind="checksum",
                            field="checksum",
                            algorithm=rule.algorithm,
                            byte_order=rule.field.endian,
                            coverage=rule.coverage,
                            covered_ranges=rule.covered_ranges,
                            exclude_field=rule.exclude_field,
                            coverage_start=rule.coverage_start,
                        )
                    ],
                )
            )
            return DraftResult(
                candidate_id=candidate.id,
                compilable=True,
                document_json=canonical(model),
                diagnostics=("Exact framing and registered checksum transferred.",),
            )
    if not isinstance(candidate.rule, FramingCandidateRule):
        return DraftResult(
            candidate_id=candidate.id,
            compilable=False,
            diagnostics=(
                candidate.compiler_reason
                or "discovery cannot compile this analytical rule independently.",
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
