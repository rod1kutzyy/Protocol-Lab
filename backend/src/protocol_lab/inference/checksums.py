"""Bounded registry checksum hypotheses and fixed-rule execution."""

from uuid import uuid5

from protocol_lab.inference.models import (
    CandidateEvidence,
    ChecksumRule,
    IntegerLocation,
    content_hash,
)
from protocol_lab.interpretation.checksums import REGISTRY, calculate, covered_bytes


def check(rule, data, cancelled=lambda: False):
    start = (
        len(data) - rule.field.offset - rule.field.width
        if rule.field_relative_to == "message_end"
        else rule.field.offset
    )
    end = start + rule.field.width
    if start < 0 or end > len(data):
        return "unknown", "checksum field outside message", None, 0
    try:
        covered = covered_bytes(
            data, start, end, rule.coverage, rule.covered_ranges, rule.exclude_field,
            rule.coverage_start,
        )
    except ValueError:
        return "unknown", "checksum covered range outside message", None, 0
    actual = int.from_bytes(data[start:end], rule.field.endian)
    expected = calculate(rule.algorithm, covered, cancelled)
    return (
        "passed" if actual == expected else "failed",
        f"{rule.algorithm}: expected={expected}, observed={actual}; "
        f"field=[{start},{end}), coverage={rule.coverage}, bytes={len(covered)}",
        (start, end),
        len(covered),
    )


def propose_checksums(
    run_id,
    snapshot,
    parent,
    messages,
    inputs,
    trials,
    operations,
    output_meter,
    cancelled=lambda: False,
):
    from protocol_lab.inference.engine import (
        Exhausted,
        anchor,
        relation_candidate,
        relation_metrics,
    )

    found, evidence, searched = [], [], 0
    if len(messages) < 3:
        return found, evidence, searched, False
    minimum = min(len(data) for _, _, data in messages)
    configurations = []
    for name in snapshot.spec.checksum_algorithms:
        width = REGISTRY[name].width // 8
        positions = [("message_end", 0)] + [
            ("message_start", offset)
            for offset in range(min(snapshot.spec.budget.max_header_bytes, minimum - width + 1))
        ]
        for relative, offset in positions:
            for endian in ("big",) if width == 1 else snapshot.spec.search.endians:
                for coverage in ("before_field", "message"):
                    for coverage_start in range(min(5, snapshot.spec.budget.max_header_bytes)):
                        configurations.append((relative, offset, name, width, endian, coverage,
                                               coverage_start))
    configurations.sort(
        key=lambda value: (value[0] != "message_end", value[6], value[1], value[2], value[4], value[5])
    )
    for relative, offset, name, width, endian, coverage, coverage_start in configurations:
        if trials.used >= trials.maximum:
            return found, evidence, searched, True
        trials.consume()
        searched += 1
        rule = ChecksumRule(
            kind="checksum_relation",
            algorithm=name,
            field=IntegerLocation(offset=offset, width=width, endian=endian),
            field_relative_to=relative,
            coverage=coverage,
            coverage_start=coverage_start,
            framing=parent.rule.framing,
        )
        cid = uuid5(run_id, f"{parent.id}:checksums:{content_hash(rule)}")
        screened = {}
        for item, message_anchor, data in messages[:8]:
            if operations.used + len(data) > operations.maximum:
                return found, evidence, searched, True
            operations.consume(len(data))
            screened[(item.stream.id, message_anchor.byte_range.start)] = check(
                rule, data, cancelled
            )
        screen_statuses = [result[0] for result in screened.values() if result[3] > 0]
        if screen_statuses.count("passed") < 3 or screen_statuses.count(
            "passed"
        ) < screen_statuses.count("failed"):
            continue
        facts, values, checked_payloads = [], set(), set()
        for item, message_anchor, data in messages:
            result = screened.get((item.stream.id, message_anchor.byte_range.start))
            if result is None:
                if operations.used + len(data) > operations.maximum:
                    return found, evidence, searched, True
                operations.consume(len(data))
                result = check(rule, data, cancelled)
            status, diagnostic, region, count = result
            if count == 0:
                status, diagnostic = "unknown", "empty checksum coverage is not support"
            loc = (
                anchor(
                    item.stream,
                    message_anchor.byte_range.start + region[0],
                    message_anchor.byte_range.start + region[1],
                )
                if region
                else message_anchor
            )
            facts.append(
                CandidateEvidence(
                    candidate_id=cid,
                    status=status,
                    anchor=loc,
                    sources=tuple(item.provenance(loc)),
                    diagnostic=diagnostic,
                    preview_hex=data[region[0] : region[1]].hex() if region else "",
                )
            )
            if status == "passed":
                checked_payloads.add(data)
                values.add(data[region[0] : region[1]])
        statuses = [f.status for f in facts]
        if statuses.count("passed") < 3 or len(checked_payloads) < 2:
            continue
        if statuses.count("passed") < statuses.count("failed"):
            continue
        metric = relation_metrics(
            "message",
            statuses,
            inputs,
            len(values),
            len(set(data for _, _, data in messages)),
        )
        candidate, facts = relation_candidate(
            run_id, snapshot, parent, rule, "checksums", inputs, facts, metric
        )
        if relative == "message_end" and offset == 0:
            candidate = candidate.model_copy(
                update={
                    "compiler_support": "interpretation-2",
                    "compiler_reason": None,
                }
            )
        try:
            output_meter.consume(
                len(candidate.model_dump_json().encode())
                + sum(len(fact.model_dump_json().encode()) + 32 for fact in facts)
            )
        except Exhausted:
            raise ValueError("max_evidence_bytes exceeded; no completed result published") from None
        found.append(candidate)
        evidence.extend(facts)
    return found, evidence, searched, False
