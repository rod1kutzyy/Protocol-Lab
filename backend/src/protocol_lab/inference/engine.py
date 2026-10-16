"""Bounded offline proposals. Screening never issues Passed; shared frame() does.

Discovery reads no holdout bytes. All retained framing rules are frozen before
evaluation, which preserves leftovers, source uncertainty and unsearched ranges.
"""

import base64
import hashlib
import json
import math
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from fractions import Fraction
from uuid import uuid4, uuid5

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import ByteRange, StreamRange
from protocol_lab.framing.engine import (
    FixedRule,
    FramingSpec,
    LengthRule,
    MarkerRule,
    StreamInput,
    frame,
)
from protocol_lab.inference.models import (
    CandidateEvaluation,
    CandidateEvidence,
    CandidateScope,
    ChecksumRule,
    CopyRelationRule,
    CounterRule,
    DelimiterRule,
    DetectorOutcome,
    EventRule,
    FramingCandidateRule,
    GroupRule,
    InferenceCandidate,
    InferenceCoverage,
    InferenceMetrics,
    InferenceRun,
    IntegerLocation,
    MappingRule,
    ProfileRule,
    RankingComponents,
    RegionRule,
    SearchRange,
    TimestampRule,
    content_hash,
)
from protocol_lab.inference.ranking import ranking_key
from protocol_lab.inference.results import EvaluationRecord
from protocol_lab.inference.sampling import SampleUnit, select_sample

VERSION = "inference-v5"
DETECTORS = {
    "checksums": "registry-checksums-a4-1",
    "framing": "bounded-framing-1",
    "structure": "structure-a2-1",
    "entropy": "profile-1",
    "groups": "message-groups-1",
    "events": "event-windows-1",
    "data_mapping": "parameter-mapping-1",
    "counters": "counter-relations-a3-1",
    "tokens": "session-copy-relations-a3-1",
    "timestamps": "timestamp-relations-a3-1",
}


@dataclass
class StreamData:
    capture: object
    stream: object
    source: StreamInput
    # Callback maps a stable range to exact original packet payload ranges.
    provenance: object = lambda anchor: ()
    wire_identity: tuple | None = None
    sequence_origin: int | None = None
    packet_times: tuple[tuple[int, int, int], ...] = ()


class Exhausted(Exception):
    pass


@dataclass
class Meter:
    maximum: int
    used: int = 0

    def consume(self, value=1):
        if self.used + value > self.maximum:
            raise Exhausted
        self.used += value


class EvidenceList(list):
    """Fail before accumulating an artifact larger than the declared output budget."""

    def __init__(self, meter):
        super().__init__()
        self.meter = meter

    def append(self, item):
        try:
            self.meter.consume(len(item.model_dump_json().encode()) + 32)
        except Exhausted:
            raise ValueError("max_evidence_bytes exceeded; no completed result published") from None
        super().append(item)

    def extend(self, items):
        for item in items:
            self.append(item)


@dataclass
class Checked:
    evidence: list = field(default_factory=list)
    messages: list = field(default_factory=list)
    complete: bool = True
    diagnostics: list = field(default_factory=list)
    explained: int = 0
    selected: int = 0


def anchor(stream, start, end):
    return StreamRange(
        stream_id=stream.id,
        reconstruction_version=stream.reconstruction_version,
        byte_range=ByteRange(start=start, end=end),
    )


def selected_ranges(snapshot, stream):
    """Explicit exclusions split ranges, never fill missing data or create new starts."""
    if not stream.included:
        return []
    ranges, cursor = [], 0
    for a, b in sorted(
        (r.byte_range.start, r.byte_range.end)
        for r in snapshot.spec.excluded_ranges
        if r.stream_id == stream.id
    ):
        if cursor < a:
            ranges.append((cursor, a))
        cursor = max(cursor, b)
    if cursor < stream.extent:
        ranges.append((cursor, stream.extent))
    return ranges


def actual_coverage(snapshot, inputs, explained=0, only_ids=None, scope_ids=None):
    totals = Counter()
    for item in inputs:
        s = item.stream
        if only_ids is not None and s.id not in only_ids:
            continue
        totals["total"] += s.extent
        if scope_ids is not None and s.id not in scope_ids:
            continue
        for left, right in selected_ranges(snapshot, s):
            totals["selected"] += right - left
            for a, b, status in item.source.ranges:
                size = max(0, min(b, right) - max(a, left))
                totals[status] += size
    return InferenceCoverage(
        stream_bytes=totals["total"],
        selected_bytes=totals["selected"],
        excluded_bytes=totals["total"] - totals["selected"],
        known_bytes=totals["known"],
        unavailable_bytes=totals["gap"] + totals["truncated"],
        ambiguous_bytes=totals["ambiguous"],
        unframed_bytes=max(0, totals["selected"] - explained),
    )


def partition(snapshot, inputs, side, include_excluded=False):
    ids = set(getattr(snapshot.spec.split, side + "_ids"))
    return [
        item
        for item in inputs
        if (item.stream.included or include_excluded)
        and (item.capture.id if snapshot.spec.split.unit == "capture" else item.stream.session_id)
        in ids
    ]


def read_range(source, start, end, meter):
    data = bytearray()
    while start < end:
        length = min(65536, end - start)
        meter.consume(length)
        part = source.read(start, length)
        if part is None:
            return None
        data.extend(part)
        start += length
    return bytes(data)


def probe_messages(data, spec, stop, cancelled):
    """Cheap geometry screening only, including chain and independent byte repetition."""
    cursor, messages = spec.start, []
    rule = spec.rule
    while cursor < len(data) and len(messages) < stop:
        if cancelled():
            raise WorkCancelled
        if isinstance(rule, FixedRule):
            end = cursor + rule.size
        elif isinstance(rule, LengthRule):
            header = cursor + rule.offset + rule.width
            if header > len(data):
                break
            total = int.from_bytes(data[cursor + rule.offset : header], rule.endian)
            total = total * rule.multiplier + rule.adjustment
            if total < rule.offset + rule.width or total <= 0 or total > spec.max_message_bytes:
                break
            end = cursor + total
        else:
            start, finish = bytes.fromhex(rule.start_hex), bytes.fromhex(rule.end_hex)
            cursor = data.find(start, cursor)
            if cursor < 0:
                break
            end = data.find(finish, cursor + len(start), cursor + spec.max_message_bytes)
            if end < 0:
                break
            end += len(finish)
        if end > len(data):
            break
        messages.append(data[cursor:end])
        cursor = end
    return messages


def structural_support(messages, spec):
    if len(messages) < 2:
        return 0
    size = min(16, min(map(len, messages)))
    skip = set()
    if isinstance(spec.rule, LengthRule):
        skip = set(range(spec.rule.offset, spec.rule.offset + spec.rule.width))
    support = 0
    for offset in range(size):
        for reverse in (False, True):
            if not reverse and offset in skip:
                continue
            values = [m[-offset - 1] if reverse else m[offset] for m in messages]
            if len(set(values)) == 1 and values[0] not in {0, 255}:
                support += 1
    return support


def patterns(data, space, budget, cancelled):
    # Bounded n-grams; same-byte padding is not an independent boundary signal.
    counters = Counter()
    scanned = min(
        len(data),
        budget.max_marker_positions,
        max(1, budget.max_sample_units // space.marker_max_bytes),
    )
    for pos in range(scanned):
        if cancelled():
            raise WorkCancelled
        for width in range(1, min(space.marker_max_bytes, len(data) - pos) + 1):
            p = data[pos : pos + width]
            if p[0] not in {0, 255} and (width == 1 or len(set(p)) > 1):
                counters[p] += 1
    ranked = sorted(
        (p for p, count in counters.items() if count >= space.min_repeated_messages),
        key=lambda p: (-min(counters[p], 100), -len(p), p),
    )
    return ranked[: space.max_marker_patterns], (
        scanned < len(data) or len(ranked) > space.max_marker_patterns
    )


def propose(snapshot, probes, direction, trials, cancelled, progress=lambda done, total: None):
    """Finite deterministic search with explicit early stopping and shared screening."""
    space, budget = snapshot.spec.search, snapshot.spec.budget
    if not probes:
        return [], False
    # Deduplicate windows before proposing parameters; duplicates are not fresh trials.
    samples = sorted(set(probes), key=lambda d: hashlib.sha256(d).hexdigest())
    markers = set(bytes.fromhex(p) for p in snapshot.spec.known_markers)
    limited = False
    for data in samples[: budget.max_probe_streams]:
        found, cut = patterns(data, space, budget, cancelled)
        markers.update(found)
        limited |= cut
    limited |= len(markers) > space.max_marker_patterns
    markers = sorted(markers, key=lambda p: (-len(p), p))[: space.max_marker_patterns]
    best, seen = {}, set()

    def test(rule, start=0):
        nonlocal limited
        if cancelled():
            raise WorkCancelled
        spec = FramingSpec(
            start=start,
            rule=rule,
            max_message_bytes=budget.max_message_bytes,
            max_pieces=min(200000, budget.max_sample_units),
        )
        sha = content_hash(spec)
        if sha in seen:
            return
        seen.add(sha)
        trials.consume()
        if trials.used % 256 == 0:
            progress(trials.used, trials.maximum)
        messages = []
        for data in samples[: budget.max_probe_streams]:
            messages.extend(probe_messages(data, spec, budget.max_screen_messages, cancelled))
        unique = set(messages)
        if len(messages) < space.min_repeated_messages or len(unique) < space.min_unique_messages:
            return
        independent = structural_support(messages, spec)
        lengths = len(set(map(len, messages)))
        if not independent and (not isinstance(rule, LengthRule) or lengths < 2):
            return
        # Screening score is not a validation status or statistical confidence.
        score = (
            (independent > 0, lengths > 1, len(messages), sum(map(len, messages)), -start)
            if isinstance(rule, LengthRule)
            else (
                lengths > 1,
                sum(map(len, messages)),
                Fraction(independent, min(map(len, messages))),
                -Fraction(sum(map(len, messages)), len(messages)),
                -start,
            )
        )
        best[sha] = (score, spec)
        if sum(v[1].rule.kind == rule.kind for v in best.values()) > budget.max_shortlist_per_kind:
            limited = True
            worst = min(
                (h for h in best if best[h][1].rule.kind == rule.kind),
                key=lambda h: (best[h][0], h),
            )
            del best[worst]

    def guided():
        for data in samples[: budget.max_probe_streams]:
            for marker in markers:
                positions, cursor = [], 0
                while len(positions) < budget.max_marker_occurrences:
                    pos = data.find(marker, cursor)
                    if pos < 0:
                        break
                    positions.append(pos)
                    cursor = pos + len(marker)
                if len(positions) < space.min_repeated_messages:
                    continue
                start = positions[0]
                if start >= budget.max_header_bytes:
                    continue
                distances = Counter(b - a for a, b in zip(positions, positions[1:], strict=False))
                for distance, _ in distances.most_common(4):
                    if (
                        space.fixed_size_min
                        <= distance
                        <= min(space.fixed_size_max, budget.max_message_bytes)
                    ):
                        yield FixedRule(kind="fixed", size=distance), start
                    for offset in range(min(budget.max_header_bytes, distance)):
                        for width in space.widths:
                            if offset + width > distance or start + offset + width > len(data):
                                continue
                            for endian in space.endians:
                                raw = int.from_bytes(
                                    data[start + offset : start + offset + width], endian
                                )
                                for mul in range(space.multiplier_min, space.multiplier_max + 1):
                                    adj = distance - raw * mul
                                    yield (
                                        (
                                            LengthRule(
                                                kind="length",
                                                offset=offset,
                                                width=width,
                                                endian=endian,
                                                multiplier=mul,
                                                adjustment=adj,
                                            ),
                                            start,
                                        )
                                        if space.adjustment_min <= adj <= space.adjustment_max
                                        else None
                                    )

    def paired():
        for begin in markers:
            for end in markers:
                yield MarkerRule(kind="markers", start_hex=begin.hex(), end_hex=end.hex()), 0

    def fixed():
        for start in range(budget.max_header_bytes):
            for size in range(
                max(space.fixed_size_min, start + 1),
                min(space.fixed_size_max, budget.max_message_bytes) + 1,
            ):
                yield FixedRule(kind="fixed", size=size), start

    def lengths():
        adjustments = sorted(
            range(space.adjustment_min, space.adjustment_max + 1), key=lambda n: (abs(n), n)
        )
        for start in range(budget.max_header_bytes):
            for offset in range(budget.max_header_bytes):
                for width in space.widths:
                    for endian in space.endians:
                        for mul in range(space.multiplier_min, space.multiplier_max + 1):
                            for adj in adjustments:
                                yield (
                                    LengthRule(
                                        kind="length",
                                        offset=offset,
                                        width=width,
                                        endian=endian,
                                        multiplier=mul,
                                        adjustment=adj,
                                    ),
                                    start,
                                )

    # Fair round-robin prevents fixed-size enumeration starving length/marker search.
    generators = [iter(guided()), iter(paired()), iter(fixed()), iter(lengths())]
    while generators:
        remaining = []
        for generator in generators:
            if trials.used >= trials.maximum:
                limited = True
                generators = []
                break
            try:
                proposal = next(generator)
            except StopIteration:
                continue
            if proposal is None:
                trials.consume()
            else:
                test(*proposal)
            remaining.append(generator)
        else:
            generators = remaining
            continue
        break
    # Retain several independent modes rather than losing all marker rules in one pool.
    choices = []
    for kind in ("length", "markers", "fixed"):
        choices.extend(
            sorted(
                (item for item in best.values() if item[1].rule.kind == kind),
                key=lambda pair: (tuple(-v for v in pair[0]), content_hash(pair[1])),
            )[: max(1, budget.max_framing_alternatives // 3)]
        )
    return [spec for _, spec in choices][: budget.max_framing_alternatives], limited


def check_framing(
    snapshot, candidate_id, spec, inputs, cancelled, meter, evaluations, output_meter=None
):
    checked = Checked(
        evidence=EvidenceList(output_meter or Meter(snapshot.spec.budget.max_evidence_bytes))
    )
    for item in inputs:
        if cancelled():
            raise WorkCancelled
        stream, source = item.stream, item.source
        checked.selected += sum(b - a for a, b in selected_ranges(snapshot, stream))
        if not stream.extent:
            continue
        last = 0
        complete_result = None

        def progress(done, total):
            nonlocal last
            last = max(last, done)

        def read(start, length, source=source):
            meter.consume(length)
            return source.read(start, length)

        def stop():
            if cancelled():
                raise WorkCancelled
            return False

        # Explicit exclusions become barriers for byte-dependent framers.
        boundaries = {0, source.extent}
        for a, b, _ in source.ranges:
            boundaries.update((a, b))
        selected = selected_ranges(snapshot, stream)
        for a, b in selected:
            boundaries.update((a, b))
        points = sorted(boundaries)
        ranges = [
            (
                a,
                b,
                source.status(a, b)
                if any(left <= a < right for left, right in selected)
                else "gap",
            )
            for a, b in zip(points, points[1:], strict=False)
        ]
        ranges = [(a, b, "gap" if st == "incomplete" else st) for a, b, st in ranges]
        # Avoid holding partial frame() results if a protective limit interrupts it.
        try:
            if spec.start > stream.extent:
                checked.evidence.append(
                    CandidateEvidence(
                        candidate_id=candidate_id,
                        status="unknown",
                        anchor=anchor(stream, 0, stream.extent),
                        diagnostic="configured start lies beyond available stream extent",
                    )
                )
                continue
            complete_result = frame(
                stream.id,
                stream.reconstruction_version,
                item.capture.id,
                item.capture.sha256,
                StreamInput(source.extent, ranges, read),
                spec,
                stop,
                progress,
            )
            evaluations.consume(len(complete_result.pieces))
        except (Exhausted, ValueError) as exc:
            if isinstance(exc, ValueError) and "max_pieces" not in str(exc):
                raise
            checked.complete = False
            checked.diagnostics.append(f"stream {stream.id}: technical search budget; unsearched")
            checked.evidence.append(
                CandidateEvidence(
                    candidate_id=candidate_id,
                    status="unknown",
                    anchor=anchor(stream, 0, stream.extent),
                    diagnostic=(
                        "search_limited: full stream not evaluated; no partial success claimed"
                    ),
                )
            )
            continue
        for piece in complete_result.pieces:
            r = piece.anchor.byte_range
            included = any(a <= r.start and r.end <= b for a, b in selected)
            overlaps_exclusion = not included
            status = (
                "not_applicable"
                if overlaps_exclusion
                else "ambiguous"
                if piece.data_status in {"ambiguous", "mixed"}
                else "unknown"
                if piece.data_status != "known" or piece.technical_limit
                else "passed"
                if piece.kind == "message"
                else "unknown"
                if piece.diagnostic
                in {
                    "incomplete_fixed_message",
                    "incomplete_length_header",
                    "incomplete_length_message",
                    "end_marker_not_found_before_stream_end",
                    "before_configured_start",
                }
                else "failed"
            )
            preview = ""
            if status == "passed":
                try:
                    data = read_range(source, r.start, r.end, meter)
                except Exhausted:
                    data, status = None, "unknown"
                    checked.complete = False
                if data is not None:
                    preview = data[:64].hex()
                    checked.messages.append((item, piece.anchor, data))
                    checked.explained += r.end - r.start
            sources = tuple(item.provenance(piece.anchor))
            if overlaps_exclusion and any(a < r.end and r.start < b for a, b in selected):
                status = "unknown"
            checked.evidence.append(
                CandidateEvidence(
                    candidate_id=candidate_id,
                    status=status,
                    anchor=piece.anchor,
                    sources=sources,
                    preview_hex=preview,
                    diagnostic=piece.diagnostic
                    if status != "unknown" or checked.complete
                    else "search_limited: payload read budget",
                )
            )
    return checked


def metrics(checked, inputs):
    # A repeated payload contributes only one applicable success. Occurrences remain evidence.
    unique = {hashlib.sha256(d).hexdigest() for _, _, d in checked.messages}
    failures = Counter(e.status for e in checked.evidence if e.status != "passed")
    n = len(unique)
    return InferenceMetrics(
        unit="message",
        eligible=n + failures["failed"] + failures["unknown"] + failures["ambiguous"],
        matched=n,
        contradicted=failures["failed"],
        unknown=failures["unknown"],
        ambiguous=failures["ambiguous"],
        not_applicable=failures["not_applicable"],
        captures=len({i.capture.id for i, _, _ in checked.messages}),
        sessions=len({i.stream.session_id for i, _, _ in checked.messages}),
        unique_messages=n,
        distinct_lengths=len({len(d) for _, _, d in checked.messages}),
    )


def candidate_for(run_id, snapshot, rule, family, direction, checked, inputs, dependencies=()):
    sha = content_hash(rule)
    id = uuid5(run_id, f"{direction}:{sha}")
    m = metrics(checked, inputs)
    support = "interpretation-1" if isinstance(rule, FramingCandidateRule) else "not_compilable"
    return InferenceCandidate(
        id=id,
        run_id=run_id,
        family=family,
        detector_version=DETECTORS[family],
        rule=rule,
        rule_sha256=sha,
        scope=CandidateScope(
            corpus_version_id=snapshot.corpus.id,
            capture_ids=tuple(c.id for c in snapshot.sources),
            session_ids=tuple(sorted({i.stream.session_id for i in inputs}, key=str)),
            direction=direction,
        ),
        dependency_ids=dependencies,
        metrics=m,
        ranking=RankingComponents(
            supporting_sessions=m.sessions,
            matched=m.matched,
            checked=m.matched + m.contradicted,
            explained_bytes=checked.explained,
            contradictions=m.contradicted,
            free_parameters=6
            if rule.kind == "length_framing"
            else 3
            if rule.kind == "marker_framing"
            else 2,
        ),
        rationale=f"{rule.kind}: {m.matched}/{m.matched + m.contradicted} unique checked units; "
        f"{m.sessions} sessions; {m.distinct_lengths} lengths",
        assumptions=snapshot.spec.assumptions,
        limitations=(
            "Discovery is sampled and bounded; TCP segment boundaries were not used.",
            "A repeated byte or successful framing does not establish field semantics.",
            "Fixed and length explanations can coexist for a single observed size.",
        ),
        compiler_support=support,
        compiler_reason=None
        if support == "interpretation-1"
        else (
            "Region/profile is conditional on its framing dependency; no standalone complete model."
        ),
    )


def propose_delimiters(run_id, snapshot, parent, messages, inputs, output_meter):
    """Find repeated in-message separators without treating them as proven fields."""
    if len(messages) < 3:
        return [], []
    patterns = {b"\x00", b"\r\n"}
    occurrence = Counter()
    message_presence = Counter()
    for _, _, data in messages:
        counts = Counter(data)
        occurrence.update({bytes([value]): count for value, count in counts.items() if count >= 2})
        message_presence.update(bytes([value]) for value, count in counts.items() if count >= 2)
        for left, right in zip(data, data[1:], strict=False):
            if left == 0x0D and right == 0x0A:
                patterns.add(b"\r\n")
    frequent = sorted(
        (
            pattern
            for pattern, count in occurrence.items()
            if count >= 4 and message_presence[pattern] >= 3
        ),
        key=lambda pattern: (-occurrence[pattern], pattern),
    )
    patterns.update(frequent[:12])
    direction = inputs[0].stream.direction
    proposed, evidence = [], []
    for delimiter in sorted(patterns, key=lambda value: (len(value), value)):
        partitions = [
            (item, anchor_, data, data.split(delimiter)) for item, anchor_, data in messages
        ]
        eligible = [
            (item, a, data, fields) for item, a, data, fields in partitions if len(fields) >= 3
        ]
        counts = Counter(len(fields) for _, _, _, fields in eligible)
        if not eligible or max(counts.values()) < 3:
            continue
        field_count, support = max(counts.items(), key=lambda value: (value[1], -value[0]))
        # Require the same repeated delimiter count on multiple distinct payloads.
        matching = [
            (item, a, data, fields)
            for item, a, data, fields in eligible
            if len(fields) == field_count
        ]
        if len({hashlib.sha256(data).digest() for _, _, data, _ in matching}) < 2:
            continue
        rule = DelimiterRule(kind="field_delimiter", delimiter_hex=delimiter.hex())
        candidate_id = uuid5(run_id, f"{direction}:{content_hash(rule)}:{parent.id}")
        checked = Checked(evidence=EvidenceList(output_meter))
        for item, a, data, fields in partitions:
            status = "passed" if len(fields) == field_count else "failed"
            checked.evidence.append(
                CandidateEvidence(
                    candidate_id=candidate_id,
                    status=status,
                    anchor=a,
                    sources=tuple(item.provenance(a)),
                    preview_hex=data[:64].hex(),
                    diagnostic=(
                        f"{len(fields) - 1} occurrences; {len(fields)} fields"
                        if status == "passed"
                        else (
                            f"counterexample: {len(fields) - 1} occurrences; "
                            f"expected {field_count - 1}"
                        )
                    ),
                )
            )
            if status == "passed":
                checked.messages.append((item, a, data))
                checked.explained += len(data)
        candidate = candidate_for(
            run_id, snapshot, rule, "structure", direction, checked, inputs, (parent.id,)
        )
        candidate = candidate.model_copy(
            update={
                "id": candidate_id,
                "rationale": (
                    f"Разделитель {delimiter.hex()} повторяется с {field_count - 1} "
                    f"полями в {support} сообщениях; структурный кандидат."
                ),
                "limitations": (
                    "Проверены только сообщения выбранного A1-фрейминга.",
                    "Экранирование, кавычки, вложенность и нулевой padding не выводились.",
                ),
            }
        )
        checked.evidence = [
            e.model_copy(update={"candidate_id": candidate.id}) for e in checked.evidence
        ]
        proposed.append(candidate)
        evidence.extend(checked.evidence)
    return proposed[:8], evidence


def propose_groups(run_id, snapshot, parent, messages, inputs, output_meter):
    """Propose short fixed-offset grouping keys; keep every sampled message visible."""
    if len(messages) < 4:
        return [], []
    direction = inputs[0].stream.direction
    width_limit = min(snapshot.spec.budget.max_header_bytes, 8)
    min_length = min(len(data) for _, _, data in messages)
    candidates, evidence = [], []
    seen = set()
    for width in (1, 2):
        if min_length < width:
            continue
        for offset in range(min(64, width_limit - width + 1)):
            for endian in ("big",) if width == 1 else ("big", "little"):
                location = IntegerLocation(offset=offset, width=width, endian=endian)
                values = [
                    int.from_bytes(data[offset : offset + width], endian) for _, _, data in messages
                ]
                counts = Counter(values)
                repeated = {value: count for value, count in counts.items() if count >= 2}
                if not 2 <= len(repeated) <= 16 or sum(repeated.values()) < 4:
                    continue
                rule = GroupRule(kind="opcode_candidate", key_fields=(location,))
                digest = content_hash(rule)
                if digest in seen:
                    continue
                seen.add(digest)
                cid = uuid5(run_id, f"{direction}:{digest}:{parent.id}")
                checked = Checked(evidence=EvidenceList(output_meter))
                for (item, a, data), value in zip(messages, values, strict=True):
                    if value in repeated:
                        checked.messages.append((item, a, data))
                        checked.explained += len(data)
                    checked.evidence.append(
                        CandidateEvidence(
                            candidate_id=cid,
                            status="passed" if value in repeated else "unknown",
                            anchor=a,
                            sources=tuple(item.provenance(a)),
                            preview_hex=data[:64].hex(),
                            diagnostic=f"key=0x{value:0{width * 2}x}; group size={counts[value]}"
                            if value in repeated
                            else f"unassigned singleton key=0x{value:0{width * 2}x}",
                        )
                    )
                candidate = candidate_for(
                    run_id, snapshot, rule, "groups", direction, checked, inputs, (parent.id,)
                )
                candidate = candidate.model_copy(
                    update={
                        "id": cid,
                        "rationale": (
                            f"Поле [{offset}, {offset + width}) разделяет "
                            f"{len(repeated)} повторяющихся групп; одиночные значения "
                            "оставлены нераспределёнными."
                        ),
                        "limitations": (
                            "Ключ найден только в выбранных сообщениях и направлении.",
                            "Смысл opcode и маски счётчиков/токенов не выводятся.",
                        ),
                    }
                )
                candidates.append(candidate)
                evidence.extend(checked.evidence)
    candidates.sort(
        key=lambda c: (
            -c.metrics.matched,
            c.metrics.unknown,
            c.rule.key_fields[0].offset,
            c.rule.key_fields[0].width,
            c.rule.key_fields[0].endian,
        )
    )
    retained = candidates[:8]
    retained_ids = {c.id for c in retained}
    return retained, [e for e in evidence if e.candidate_id in retained_ids]


def relation_candidate(
    run_id,
    snapshot,
    parent,
    rule,
    family,
    inputs,
    evidence,
    metrics_value,
    dependencies=None,
    direction=None,
):
    digest = content_hash(rule)
    candidate_id = uuid5(run_id, f"{parent.id}:{family}:{digest}")
    evidence = [item.model_copy(update={"candidate_id": candidate_id}) for item in evidence]
    return (
        InferenceCandidate(
            id=candidate_id,
            run_id=run_id,
            family=family,
            detector_version=DETECTORS[family],
            rule=rule,
            rule_sha256=digest,
            scope=CandidateScope(
                corpus_version_id=snapshot.corpus.id,
                capture_ids=tuple(sorted({item.capture.id for item in inputs}, key=str)),
                session_ids=tuple(sorted({item.stream.session_id for item in inputs}, key=str)),
                direction=direction or parent.scope.direction,
            ),
            dependency_ids=tuple(dependencies or (parent.id,)),
            metrics=metrics_value,
            ranking=RankingComponents(
                supporting_sessions=metrics_value.sessions,
                matched=metrics_value.matched,
                checked=metrics_value.matched + metrics_value.contradicted,
                explained_bytes=sum(
                    item.anchor.byte_range.end - item.anchor.byte_range.start
                    for item in evidence
                    if item.status == "passed" and item.anchor is not None
                ),
                contradictions=metrics_value.contradicted,
                free_parameters=3,
            ),
            rationale=(
                f"{rule.kind}: {metrics_value.matched} matched, "
                f"{metrics_value.contradicted} contradicted, "
                f"{metrics_value.unknown} unknown; relation is a testable candidate."
            ),
            assumptions=snapshot.spec.assumptions,
            limitations=(
                "Discovery is bounded and conditional on the frozen framing rule.",
                "A byte relation does not establish the protocol field's semantic meaning.",
            ),
            compiler_support="interpretation-2"
            if isinstance(rule, (CounterRule, TimestampRule))
            else "not_compilable",
            compiler_reason=None
            if isinstance(rule, (CounterRule, TimestampRule))
            else "Cross-message evidence requires the typed corpus evaluator.",
        ),
        evidence,
    )


def relation_metrics(unit, statuses, inputs, distinct_values=0, unique_messages=0):
    counts = Counter(statuses)
    applicable = sum(counts[status] for status in ("passed", "failed", "unknown", "ambiguous"))
    return InferenceMetrics(
        unit=unit,
        eligible=applicable,
        matched=counts["passed"],
        contradicted=counts["failed"],
        unknown=counts["unknown"],
        ambiguous=counts["ambiguous"],
        not_applicable=counts["not_applicable"],
        captures=len({item.capture.id for item in inputs}),
        sessions=len({item.stream.session_id for item in inputs}),
        unique_messages=unique_messages,
        distinct_values=distinct_values,
        distinct_lengths=0,
    )


def propose_counters(run_id, snapshot, parent, messages, inputs, trials, output_meter):
    """Infer bounded per-session transitions from stream order, never packet order."""
    if len(messages) < 3:
        return [], [], 0
    by_stream = defaultdict(list)
    for item, anchor_, data in messages:
        by_stream[item.stream.id].append((item, anchor_, data))
    width_limit = min(snapshot.spec.budget.max_header_bytes, 32)
    found, all_evidence, searched = [], [], 0
    for width in (1, 2, 4, 8):
        for offset in range(width_limit):
            if offset + width > min(map(lambda row: len(row[2]), messages)):
                break
            for endian in snapshot.spec.search.endians:
                field = IntegerLocation(offset=offset, width=width, endian=endian)
                for step in ("fixed", "message_length", "payload_length"):
                    increments = (1, 2, 3) if step == "fixed" else (1,)
                    for increment in increments:
                        if trials.used >= trials.maximum:
                            return found, all_evidence, searched
                        trials.consume()
                        searched += 1
                        rule = CounterRule(
                            kind="counter",
                            field=field,
                            step=step,
                            increment=increment,
                            scope="session",
                            wrap=True,
                            framing=parent.rule.framing,
                        )
                        candidate_id = uuid5(run_id, f"{parent.id}:counters:{content_hash(rule)}")
                        emitted, statuses, distinct = EvidenceList(output_meter), [], set()
                        for items in by_stream.values():
                            items.sort(key=lambda row: row[1].byte_range.start)
                            for (_previous, previous_anchor, previous_data), (
                                current,
                                current_anchor,
                                current_data,
                            ) in zip(items, items[1:], strict=False):
                                start = previous_anchor.byte_range.start + offset
                                end = current_anchor.byte_range.start + offset + width
                                fact_anchor = anchor(current.stream, start, end)
                                contiguous = (
                                    previous_anchor.byte_range.end
                                    == current_anchor.byte_range.start
                                )
                                if not contiguous:
                                    status = "unknown"
                                    diagnostic = (
                                        "unobserved bytes between messages; transition unknown"
                                    )
                                else:
                                    before = int.from_bytes(
                                        previous_data[offset : offset + width], endian
                                    )
                                    after = int.from_bytes(
                                        current_data[offset : offset + width], endian
                                    )
                                    delta = (
                                        increment
                                        if step == "fixed"
                                        else increment * len(previous_data)
                                        if step == "message_length"
                                        else increment * max(0, len(previous_data) - offset - width)
                                    )
                                    expected = (before + delta) % (1 << (width * 8))
                                    status = "passed" if after == expected else "failed"
                                    diagnostic = (
                                        f"{before} → {after}; expected {expected} "
                                        f"modulo 2^{width * 8}"
                                    )
                                    distinct.update((before, after))
                                statuses.append(status)
                                emitted.append(
                                    CandidateEvidence(
                                        candidate_id=candidate_id,
                                        status=status,
                                        anchor=fact_anchor,
                                        sources=tuple(current.provenance(fact_anchor)),
                                        preview_hex=current_data[offset : offset + width].hex(),
                                        diagnostic=diagnostic,
                                    )
                                )
                        if statuses.count("passed") < 2:
                            continue
                        m = relation_metrics(
                            "transition", statuses, inputs, len(distinct), len(messages)
                        )
                        candidate, emitted = relation_candidate(
                            run_id, snapshot, parent, rule, "counters", inputs, emitted, m
                        )
                        found.append(candidate)
                        all_evidence.extend(emitted)
    found.sort(
        key=lambda item: (
            -item.metrics.matched,
            item.metrics.contradicted,
            item.metrics.unknown,
            item.rule.field.offset,
            item.rule.field.width,
            item.rule.step,
        )
    )
    retained = found[:8]
    ids = {item.id for item in retained}
    return retained, [item for item in all_evidence if item.candidate_id in ids], searched


def message_time_interval(item, message_anchor):
    ranges = item.packet_times
    ends = tuple(right for _, right, _ in ranges)
    cursor = bisect_right(ends, message_anchor.byte_range.start)
    times = []
    while cursor < len(ranges) and ranges[cursor][0] < message_anchor.byte_range.end:
        left, right, timestamp = ranges[cursor]
        if left < message_anchor.byte_range.end and message_anchor.byte_range.start < right:
            times.append(timestamp)
        cursor += 1
    return (min(times), max(times)) if times else None


def propose_timestamps(run_id, snapshot, parent, messages, inputs, trials, output_meter):
    """Compare fixed timestamp fields to packet-time intervals or session elapsed time."""
    timed = [
        (item, a, data, interval)
        for item, a, data in messages
        if (interval := message_time_interval(item, a)) is not None
    ]
    if len(timed) < 3:
        return [], [], 0
    width_limit = min(snapshot.spec.budget.max_header_bytes, min(len(d) for _, _, d, _ in timed))
    found, all_evidence, searched = [], [], 0
    for width in (4, 8):
        if width > width_limit:
            continue
        for offset in range(width_limit - width + 1):
            for endian in snapshot.spec.search.endians:
                for signed, unit, scale in (
                    (signed, unit, scale)
                    for signed in (False, True)
                    for unit, scale in (
                        (unit, {"s": 1_000_000_000, "ms": 1_000_000, "us": 1_000, "ns": 1}[unit])
                        for unit in snapshot.spec.timestamp_units
                    )
                ):
                    values = [
                        int.from_bytes(d[offset : offset + width], endian, signed=signed)
                        for _, _, d, _ in timed
                    ]
                    times = [sum(interval) // 2 for _, _, _, interval in timed]
                    for epoch in snapshot.spec.timestamp_epochs:
                        if trials.used >= trials.maximum:
                            return found, all_evidence, searched
                        trials.consume()
                        searched += 1
                        if epoch == "unix":
                            offsets = [t - v * scale for t, v in zip(times, values, strict=True)]
                            correction = int(Decimal(str(sorted(offsets)[len(offsets) // 2])))
                            residuals = [
                                abs(t - (v * scale + correction))
                                for t, v in zip(times, values, strict=True)
                            ]
                            # Require a shared offset to explain all samples within a bounded
                            # capture-time uncertainty; per-message tuning is not allowed.
                            tolerance = max(
                                5_000_000,
                                max(right - left for _, _, _, (left, right) in timed),
                            )
                            if max(residuals) > tolerance:
                                continue
                        else:
                            by_session = defaultdict(list)
                            for row, value, timestamp in zip(timed, values, times, strict=True):
                                by_session[row[0].stream.session_id].append((row, value, timestamp))
                            residuals = {}
                            for rows in by_session.values():
                                rows.sort(key=lambda entry: entry[0][1].byte_range.start)
                                if len(rows) < 2:
                                    continue
                                first_value, first_time = rows[0][1], rows[0][2]
                                for row, value, stamp in rows:
                                    key = (row[0].stream.id, row[1].byte_range.start)
                                    residuals[key] = abs(
                                        (stamp - first_time) - (value - first_value) * scale
                                    )
                            if len(residuals) < 3:
                                continue
                            correction = 0
                            tolerance = max(
                                5_000_000,
                                max(right - left for _, _, _, (left, right) in timed),
                            )
                            if max(residuals.values()) > tolerance:
                                continue
                        rule = TimestampRule(
                            kind="timestamp_candidate"
                            if epoch == "unix"
                            else "relative_clock_candidate",
                            field=IntegerLocation(
                                offset=offset,
                                width=width,
                                endian=endian,
                                signed=signed,
                            ),
                            unit=unit,
                            epoch=epoch,
                            clock_offset_ns=str(correction),
                            tolerance_ns=tolerance,
                            framing=parent.rule.framing,
                        )
                        cid = uuid5(run_id, f"{parent.id}:timestamps:{content_hash(rule)}")
                        emitted = EvidenceList(output_meter)
                        for item, a, data, interval in timed:
                            value = int.from_bytes(
                                data[offset : offset + width], endian, signed=signed
                            )
                            observed = sum(interval) // 2
                            if epoch == "unix":
                                status = (
                                    "passed"
                                    if abs(observed - (value * scale + correction)) <= tolerance
                                    else "failed"
                                )
                            else:
                                error = residuals.get((item.stream.id, a.byte_range.start))
                                status = (
                                    "unknown"
                                    if error is None
                                    else "passed"
                                    if error <= tolerance
                                    else "failed"
                                )
                            loc = anchor(
                                item.stream,
                                a.byte_range.start + offset,
                                a.byte_range.start + offset + width,
                            )
                            emitted.append(
                                CandidateEvidence(
                                    candidate_id=cid,
                                    status=status,
                                    anchor=loc,
                                    sources=tuple(item.provenance(loc)),
                                    preview_hex=data[offset : offset + width].hex(),
                                    diagnostic=(
                                        f"{value} {unit}; packet interval "
                                        f"[{interval[0]}, {interval[1]}] ns; "
                                        f"shared offset {correction} ns, tolerance {tolerance} ns"
                                        if epoch == "unix"
                                        else (
                                            f"{value} {unit}; elapsed-time relation tested "
                                            "relative to session start"
                                        )
                                    ),
                                )
                            )
                        statuses = [e.status for e in emitted]
                        m = relation_metrics(
                            "message", statuses, inputs, len(set(values)), len(timed)
                        )
                        candidate, emitted = relation_candidate(
                            run_id, snapshot, parent, rule, "timestamps", inputs, emitted, m
                        )
                        found.append(candidate)
                        all_evidence.extend(emitted)
    found.sort(
        key=lambda item: (
            -item.metrics.matched,
            item.metrics.contradicted,
            item.rule.tolerance_ns,
            item.rule.field.offset,
            item.rule.unit,
        )
    )
    retained = found[:8]
    ids = {item.id for item in retained}
    return retained, [item for item in all_evidence if item.candidate_id in ids], searched


def propose_session_regions(run_id, snapshot, parent, messages, inputs, trials, output_meter):
    """Find per-session stable bytes that vary across independent observed sessions."""
    grouped = defaultdict(list)
    for row in messages:
        grouped[row[0].stream.session_id].append(row)
    groups = {key: rows for key, rows in grouped.items() if len(rows) >= 2}
    if len(groups) < 2:
        return [], [], 0
    width_limit = min(
        snapshot.spec.budget.max_header_bytes, 32, min(len(d) for _, _, d in messages)
    )
    found, all_evidence, searched = [], [], 0
    for width in (4, 8):
        if width > width_limit:
            continue
        for offset in range(width_limit - width + 1):
            if trials.used >= trials.maximum:
                return found, all_evidence, searched
            trials.consume()
            searched += 1
            values_by_session = {
                session: {data[offset : offset + width] for _, _, data in rows}
                for session, rows in groups.items()
            }
            stable_values = {
                next(iter(values)) for values in values_by_session.values() if len(values) == 1
            }
            if sum(len(values) == 1 for values in values_by_session.values()) < 2:
                continue
            if len(stable_values) < 2:
                continue
            rule = RegionRule(
                kind="session_stable_region",
                offset=offset,
                length=width,
                relation_scope="session",
                framing=parent.rule.framing,
            )
            cid = uuid5(run_id, f"{parent.id}:tokens:{content_hash(rule)}")
            emitted = EvidenceList(output_meter)
            for session, rows in sorted(groups.items(), key=lambda pair: str(pair[0])):
                item, a, data = rows[0]
                region = anchor(
                    item.stream, a.byte_range.start + offset, a.byte_range.start + offset + width
                )
                value = data[offset : offset + width]
                status = "passed" if len(values_by_session[session]) == 1 else "failed"
                emitted.append(
                    CandidateEvidence(
                        candidate_id=cid,
                        status=status,
                        anchor=region,
                        sources=tuple(item.provenance(region)),
                        preview_hex=value.hex(),
                        diagnostic=(
                            f"stable in {len(rows)} messages of session {session}; "
                            "differs across sessions"
                            if status == "passed"
                            else (
                                f"counterexample: {len(values_by_session[session])} values "
                                "in session"
                            )
                        ),
                    )
                )
            m = relation_metrics(
                "session",
                [item.status for item in emitted],
                inputs,
                len(stable_values),
                sum(map(len, groups.values())),
            )
            candidate, emitted = relation_candidate(
                run_id, snapshot, parent, rule, "tokens", inputs, emitted, m
            )
            candidate = candidate.model_copy(
                update={
                    "rationale": (
                        f"Byte region [{offset}, {offset + width}) is stable within "
                        f"{len(groups)} sessions and varies between them."
                    ),
                    "limitations": (
                        "Session independence is not inferred from tuple identity.",
                        "Without a known connection start, only first-observed stability is shown.",
                    ),
                }
            )
            found.append(candidate)
            all_evidence.extend(emitted)
    retained = found[:8]
    ids = {item.id for item in retained}
    return retained, [item for item in all_evidence if item.candidate_id in ids], searched


def propose_copied_values(
    run_id,
    snapshot,
    parent,
    by_direction,
    parent_ids,
    inputs,
    trials,
    output_meter,
    source_direction,
):
    """Find exact values observed later in the reverse direction, using packet time."""
    if set(by_direction) != {"a_to_b", "b_to_a"}:
        return [], [], 0
    found, all_evidence, searched = [], [], 0
    max_offset = min(snapshot.spec.budget.max_header_bytes, 32)
    for width in (4, 8):
        for source_offset in range(max_offset - width + 1):
            for target_offset in range(max_offset - width + 1):
                if trials.used >= trials.maximum:
                    return found, all_evidence, searched
                trials.consume()
                searched += 1
                pairs = []
                for direction in (source_direction,):
                    target_direction = "b_to_a" if direction == "a_to_b" else "a_to_b"
                    src_by_session, dst_by_session = defaultdict(list), defaultdict(list)
                    for item, a, data in by_direction[direction]:
                        interval = message_time_interval(item, a)
                        if interval and len(data) >= source_offset + width:
                            value = data[source_offset : source_offset + width]
                            src_by_session[item.stream.session_id].append(
                                (item, a, data, value, interval)
                            )
                    for item, a, data in by_direction[target_direction]:
                        interval = message_time_interval(item, a)
                        if interval and len(data) >= target_offset + width:
                            value = data[target_offset : target_offset + width]
                            dst_by_session[item.stream.session_id].append(
                                (item, a, data, value, interval)
                            )
                    for session in set(src_by_session) & set(dst_by_session):
                        targets = defaultdict(list)
                        for row in dst_by_session[session]:
                            targets[row[3]].append(row)
                        paired_values = set()
                        for source_row in src_by_session[session]:
                            value = source_row[3]
                            if value in paired_values:
                                continue
                            target_row = next(
                                (
                                    target
                                    for target in targets.get(value, ())
                                    if target[4][0] >= source_row[4][1]
                                ),
                                None,
                            )
                            if target_row is not None:
                                paired_values.add(value)
                                pairs.append((source_direction, source_row, target_row))
                distinct = {pair[1][3] for pair in pairs}
                if len(distinct) < 2 or not pairs:
                    continue
                rule = CopyRelationRule(
                    kind="copied_value",
                    source_offset=source_offset,
                    target_offset=target_offset,
                    length=width,
                    source_direction=source_direction,
                    framing=parent.rule.framing,
                )
                cid = uuid5(run_id, f"{parent.id}:tokens:{content_hash(rule)}")
                emitted = EvidenceList(output_meter)
                emitted_sessions = set()
                for direction, source_row, target_row in pairs:
                    src_item, src_anchor, src_data, value, _ = source_row
                    dst_item, dst_anchor, dst_data, _, _ = target_row
                    src_loc = anchor(
                        src_item.stream,
                        src_anchor.byte_range.start + source_offset,
                        src_anchor.byte_range.start + source_offset + width,
                    )
                    dst_loc = anchor(
                        dst_item.stream,
                        dst_anchor.byte_range.start + target_offset,
                        dst_anchor.byte_range.start + target_offset + width,
                    )
                    emitted_sessions.add(src_item.stream.session_id)
                    emitted.extend(
                        (
                            CandidateEvidence(
                                candidate_id=cid,
                                status="passed",
                                anchor=src_loc,
                                sources=tuple(src_item.provenance(src_loc)),
                                preview_hex=value.hex(),
                                diagnostic=(
                                    f"source occurrence ({direction}); exact value appears "
                                    "later in reverse direction"
                                ),
                            ),
                            CandidateEvidence(
                                candidate_id=cid,
                                status="passed",
                                anchor=dst_loc,
                                sources=tuple(dst_item.provenance(dst_loc)),
                                preview_hex=value.hex(),
                                diagnostic=(
                                    f"copied occurrence from [{source_offset}, "
                                    f"{source_offset + width}) at target offset {target_offset}"
                                ),
                            ),
                        )
                    )
                    if len(emitted) >= 200:
                        break
                m = relation_metrics(
                    "session",
                    ["passed"] * len(emitted_sessions),
                    inputs,
                    len(distinct),
                    len(pairs),
                )
                candidate, emitted = relation_candidate(
                    run_id,
                    snapshot,
                    parent,
                    rule,
                    "tokens",
                    inputs,
                    emitted,
                    m,
                    dependencies=parent_ids,
                    direction="both",
                )
                found.append(candidate)
                all_evidence.extend(emitted)
    found.sort(
        key=lambda item: (
            -item.metrics.distinct_values,
            -item.metrics.matched,
            item.rule.source_offset,
            item.rule.target_offset,
        )
    )
    retained = found[:8]
    ids = {item.id for item in retained}
    return retained, [item for item in all_evidence if item.candidate_id in ids], searched


def propose_events(run_id, snapshot, parent, messages, inputs, output_meter):
    events = snapshot.events
    if not events or not messages:
        return [], [], False, 0
    before, after = snapshot.spec.event_before_ns, snapshot.spec.event_after_ns
    offsets = {log.clock_offset_ns for log in snapshot.spec.logs}
    rule_offset = next(iter(offsets)) if len(offsets) == 1 else "0"
    found, evidence = [], []
    event_limit = snapshot.spec.budget.max_event_windows // max(len(messages), 1)
    selected_events = events[:event_limit]
    limited = len(selected_events) < len(events)
    if not selected_events:
        return [], [], bool(events), 0
    windows_searched = 0
    for direction in sorted({item.stream.direction for item, _, _ in messages}):
        directional = [
            (item, a, data) for item, a, data in messages if item.stream.direction == direction
        ]
        timestamp_indexes = {}
        for item, _, _ in directional:
            if item.stream.id not in timestamp_indexes:
                ranges = item.packet_times
                timestamp_indexes[item.stream.id] = (ranges, tuple(right for _, right, _ in ranges))
        times_by_message = []
        for item, a, _data in directional:
            ranges, ends = timestamp_indexes[item.stream.id]
            times = []
            index = bisect_right(ends, a.byte_range.start)
            while index < len(ranges) and ranges[index][0] < a.byte_range.end:
                left, right, timestamp = ranges[index]
                if left < a.byte_range.end and a.byte_range.start < right:
                    times.append(timestamp)
                index += 1
            times_by_message.append((min(times), max(times)) if times else None)
        if not any(times_by_message):
            continue
        windows_searched += len(selected_events) * len(directional)
        rule = EventRule(
            kind="event_association",
            before_ns=before,
            after_ns=after,
            clock_offset_ns=rule_offset,
        )
        candidate_id = uuid5(run_id, f"{direction}:{content_hash(rule)}:{parent.id}")
        matches_by_event = []
        events_by_message = [[] for _ in directional]
        for event_index, event in enumerate(selected_events):
            timestamp = int(event.timestamp_ns)
            matches = [
                index
                for index, interval in enumerate(times_by_message)
                if interval is not None
                and interval[1] >= timestamp - before
                and interval[0] <= timestamp + after
            ]
            matches_by_event.append(matches)
            for index in matches:
                events_by_message[index].append(event_index)
        event_results = []
        for event_index, event in enumerate(selected_events):
            matches = matches_by_event[event_index]
            conflict = any(len(events_by_message[index]) > 1 for index in matches)
            status = "unknown" if not matches else "ambiguous" if conflict else "passed"
            chosen = matches[0] if matches else None
            item, a, data = directional[chosen] if chosen is not None else (None, None, b"")
            event_results.append((event, status, item, a, data, len(matches)))
        matched = sum(status == "passed" for _, status, *_ in event_results)
        ambiguous = sum(status == "ambiguous" for _, status, *_ in event_results)
        unknown = sum(status == "unknown" for _, status, *_ in event_results)
        metrics_value = InferenceMetrics(
            unit="event",
            eligible=len(event_results),
            matched=matched,
            contradicted=0,
            unknown=unknown,
            ambiguous=ambiguous,
            not_applicable=0,
            captures=len({item.capture.id for item, _, _ in directional}),
            sessions=len({item.stream.session_id for item, _, _ in directional}),
            unique_messages=len(
                {
                    hashlib.sha256(data).digest()
                    for _, status, _, _, data, _ in event_results
                    if status == "passed"
                }
            ),
        )
        for event, status, item, a, data, count in event_results:
            try:
                output_meter.consume(256 + len(data[:64]))
            except Exhausted:
                raise ValueError(
                    "max_evidence_bytes exceeded; no completed result published"
                ) from None
            evidence.append(
                CandidateEvidence(
                    candidate_id=candidate_id,
                    status=status,
                    anchor=a,
                    sources=tuple(item.provenance(a)) if item is not None else (),
                    event_id=event.id,
                    preview_hex=data[:64].hex(),
                    diagnostic=(
                        f"{count} messages in the configured event window"
                        if count
                        else "no timestamped message in the configured event window"
                    ),
                )
            )
        for index, (item, a, data) in enumerate(directional):
            interval = times_by_message[index]
            if interval is None or events_by_message[index]:
                continue
            try:
                output_meter.consume(256 + len(data[:64]))
            except Exhausted:
                raise ValueError(
                    "max_evidence_bytes exceeded; no completed result published"
                ) from None
            evidence.append(
                CandidateEvidence(
                    candidate_id=candidate_id,
                    status="not_applicable",
                    anchor=a,
                    sources=tuple(item.provenance(a)),
                    preview_hex=data[:64].hex(),
                    diagnostic="timestamped message lies outside every selected event window",
                )
            )
        found.append(
            InferenceCandidate(
                id=candidate_id,
                run_id=run_id,
                family="events",
                detector_version=DETECTORS["events"],
                rule=rule,
                rule_sha256=content_hash(rule),
                scope=CandidateScope(
                    corpus_version_id=snapshot.corpus.id,
                    capture_ids=tuple(c.id for c in snapshot.sources),
                    session_ids=tuple(
                        sorted({i.stream.session_id for i, _, _ in directional}, key=str)
                    ),
                    direction=direction,
                ),
                dependency_ids=(parent.id,),
                metrics=metrics_value,
                ranking=RankingComponents(
                    supporting_sessions=metrics_value.sessions,
                    matched=matched,
                    checked=matched,
                    explained_bytes=sum(
                        len(data)
                        for _, status, _, _, data, _ in event_results
                        if status == "passed"
                    ),
                    contradictions=0,
                    free_parameters=2,
                ),
                rationale=(
                    f"{matched} of {len(event_results)} logged events have a timestamped "
                    "message in the configured window; temporal evidence only."
                ),
                assumptions=snapshot.spec.assumptions,
                limitations=(
                    "Packet timestamps and the frozen action-log clock correction are required.",
                    "Overlapping windows are ambiguous; time proximity does not prove causation.",
                    "Per-log offsets remain in the snapshot when selected logs differ.",
                    "Evidence is conditional on the retained framing candidate.",
                ),
                compiler_support="not_compilable",
                compiler_reason="Temporal association is evidence, not a parsing rule.",
            )
        )
    return found, evidence, limited, windows_searched


def propose_mappings(run_id, snapshot, inputs, scan_meter, trial_meter, output_meter):
    """Search bounded known stream runs for explicitly selected parameter encodings."""
    if not snapshot.spec.parameters:
        return [], [], False
    events = {event.id: event for event in snapshot.events}
    event_values = []
    for parameter in snapshot.spec.parameters:
        if parameter.text is not None:
            event_values.append((parameter.parameter_path or ("explicit",), None, parameter.text))
            continue
        for event_id in parameter.event_ids:
            event = events.get(event_id)
            if event is None:
                continue
            try:
                value = json.loads(event.parameters_json, parse_float=Decimal)
                for part in parameter.parameter_path:
                    value = value[part] if isinstance(value, dict) else value[int(part)]
            except (ValueError, TypeError, KeyError, IndexError):
                continue
            event_values.append((parameter.parameter_path, event_id, value))
            if len(event_values) >= snapshot.spec.budget.max_sample_messages:
                break
        if len(event_values) >= snapshot.spec.budget.max_sample_messages:
            break
    if not event_values:
        return [], [], False
    input_limited = any(
        parameter.log_id is not None for parameter in snapshot.spec.parameters
    ) and (len(event_values) >= snapshot.spec.budget.max_sample_messages)
    representations = {}
    for path, event_id, value in event_values:
        if isinstance(value, str):
            for encoding in ("ascii", "utf-8", "utf-16le", "utf-16be"):
                try:
                    raw = value.encode(encoding, errors="strict")
                except UnicodeEncodeError:
                    continue
                for bom in (False, True) if encoding.startswith("utf-16") else (False,):
                    encoded_raw = raw
                    if bom:
                        encoded_raw = (b"\xff\xfe" if encoding == "utf-16le" else b"\xfe\xff") + raw
                    for b64 in ("none", "standard", "urlsafe"):
                        encoded = encoded_raw
                        if b64 != "none":
                            encoded = (
                                base64.urlsafe_b64encode(encoded_raw)
                                if b64 == "urlsafe"
                                else base64.b64encode(encoded_raw)
                            )
                        representations.setdefault((path, encoding, b64, bom, None), []).append(
                            (event_id, value, encoded)
                        )
        elif isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
            try:
                integer_value = int(value)
                if integer_value == value:
                    representations.setdefault((path, "decimal", "none", False, None), []).append(
                        (event_id, value, str(integer_value).encode("ascii"))
                    )
                    for width in snapshot.spec.search.widths:
                        for endian in snapshot.spec.search.endians:
                            try:
                                raw = integer_value.to_bytes(
                                    width, endian, signed=integer_value < 0
                                )
                            except OverflowError:
                                continue
                            loc = IntegerLocation(
                                offset=0, width=width, endian=endian, signed=integer_value < 0
                            )
                            representations.setdefault(
                                (path, "integer", "none", False, loc), []
                            ).append((event_id, value, raw))
            except (ValueError, OverflowError):
                continue
    if not representations:
        return [], [], False
    corpus = []
    limited = False
    for item in inputs:
        if not item.stream.included:
            continue
        for left, right in item.source.known_runs(0):
            position = left
            run_bytes = bytearray()
            while position < right:
                size = min(65536, right - position)
                try:
                    data = read_range(item.source, position, position + size, scan_meter)
                except Exhausted:
                    limited = True
                    break
                run_bytes.extend(data)
                position += size
            if run_bytes:
                corpus.append((item, left, bytes(run_bytes)))
            if limited:
                break
        if limited:
            break
    found, evidence = [], []
    seen_representations = set()
    encoding_order = {
        "ascii": 0,
        "utf-8": 1,
        "utf-16le": 2,
        "utf-16be": 3,
        "decimal": 4,
        "integer": 5,
    }
    for (path, encoding, b64, bom, integer), examples in sorted(
        representations.items(),
        key=lambda entry: (
            entry[0][0],
            encoding_order[entry[0][1]],
            entry[0][2],
            entry[0][3],
            str(entry[0][4]),
        ),
    ):
        if len({str(value) for _, value, _ in examples}) < 2:
            continue
        signature = (
            path,
            tuple(sorted((str(value), pattern.hex()) for _, value, pattern in examples)),
        )
        if signature in seen_representations:
            continue
        seen_representations.add(signature)
        rule = MappingRule(
            kind="parameter_mapping",
            parameter_path=path,
            encoding=encoding,
            base64=b64,
            bom=bom,
            integer=integer,
        )
        pattern_hits = {}
        for event_id, value, pattern in examples:
            if not pattern or len(pattern) > snapshot.spec.budget.max_decoded_field_bytes:
                continue
            for item, chunk_start, data in corpus:
                try:
                    trial_meter.consume()
                    scan_meter.consume(len(data))
                except Exhausted:
                    limited = True
                    break
                pos = data.find(pattern)
                while pos >= 0:
                    start = chunk_start + pos
                    a = anchor(item.stream, start, start + len(pattern))
                    hits = pattern_hits.setdefault((event_id, str(value)), [])
                    if len(hits) >= snapshot.spec.budget.max_marker_occurrences:
                        limited = True
                        break
                    hits.append((item, a, pattern))
                    pos = data.find(pattern, pos + 1)
                if limited:
                    break
            if limited:
                break
        if limited:
            break
        for direction in sorted({item.stream.direction for item in inputs if item.stream.included}):
            directional_examples = examples
            directional_hits = {
                key: rows
                for key, rows in pattern_hits.items()
                if any(item.stream.direction == direction for item, _, _ in rows)
            }
            if not directional_hits:
                continue
            candidate_id = uuid5(run_id, f"{direction}:{content_hash(rule)}")
            statuses = []
            for event_id, value, _pattern in directional_examples:
                hits = [
                    row
                    for row in directional_hits.get((event_id, str(value)), [])
                    if row[0].stream.direction == direction
                ]
                statuses.append((event_id, value, hits))
            matched = sum(bool(hits) for _, _, hits in statuses)
            unknown = len(statuses) - matched
            unique_messages = len(
                {
                    (a.stream_id, a.byte_range.start, a.byte_range.end)
                    for _, _, hits in statuses
                    for _, a, _ in hits
                }
            )
            m = InferenceMetrics(
                unit="message",
                eligible=len(statuses),
                matched=matched,
                contradicted=0,
                unknown=unknown,
                ambiguous=0,
                not_applicable=0,
                captures=len(
                    {item.capture.id for rows in directional_hits.values() for item, _, _ in rows}
                ),
                sessions=len(
                    {
                        item.stream.session_id
                        for rows in directional_hits.values()
                        for item, _, _ in rows
                    }
                ),
                unique_messages=unique_messages,
            )
            for event_id, _value, hits in statuses:
                if hits:
                    for item, a, raw in hits[:16]:
                        try:
                            output_meter.consume(256 + len(raw))
                        except Exhausted:
                            raise ValueError(
                                "max_evidence_bytes exceeded; no completed result published"
                            ) from None
                        evidence.append(
                            CandidateEvidence(
                                candidate_id=candidate_id,
                                status="passed",
                                anchor=a,
                                sources=tuple(item.provenance(a)),
                                event_id=event_id,
                                preview_hex=raw[:64].hex(),
                                diagnostic=f"Exact {encoding}/{b64} representation found",
                            )
                        )
                else:
                    evidence.append(
                        CandidateEvidence(
                            candidate_id=candidate_id,
                            status="unknown",
                            event_id=event_id,
                            diagnostic=(
                                "No exact match in scanned known ranges; "
                                "this is not a contradiction"
                            ),
                        )
                    )
            found.append(
                InferenceCandidate(
                    id=candidate_id,
                    run_id=run_id,
                    family="data_mapping",
                    detector_version=DETECTORS["data_mapping"],
                    rule=rule,
                    rule_sha256=content_hash(rule),
                    scope=CandidateScope(
                        corpus_version_id=snapshot.corpus.id,
                        capture_ids=tuple(c.id for c in snapshot.sources),
                        session_ids=tuple(
                            sorted(
                                {
                                    item.stream.session_id
                                    for rows in directional_hits.values()
                                    for item, _, _ in rows
                                },
                                key=str,
                            )
                        ),
                        direction=direction,
                    ),
                    metrics=m,
                    ranking=RankingComponents(
                        supporting_sessions=m.sessions,
                        matched=matched,
                        checked=matched,
                        explained_bytes=sum(
                            len(raw) for rows in directional_hits.values() for _, _, raw in rows
                        ),
                        contradictions=0,
                        free_parameters=2,
                    ),
                    rationale=(
                        f"Exact {encoding}/{b64} bytes found for {matched} of "
                        f"{len(statuses)} selected values; matches are not independent proof."
                    ),
                    assumptions=snapshot.spec.assumptions,
                    limitations=(
                        "Only explicitly selected encodings and known stream ranges were searched.",
                        "Short/common values can match by chance; one value is weak evidence.",
                    ),
                    compiler_support="not_compilable",
                    compiler_reason="Parameter-to-byte evidence is not a standalone parsing rule.",
                )
            )
    return found, evidence, limited or input_limited


def discover(
    snapshot,
    inputs,
    run_id=None,
    parent_id=None,
    cancelled=lambda: False,
    progress=lambda message, done, total: None,
):
    if snapshot.spec.mode != "discover":
        raise ValueError("Discovery requires mode=discover")
    run_id = run_id or uuid4()
    inputs = sorted(inputs, key=lambda i: str(i.stream.id))
    discovery = partition(snapshot, inputs, "discovery")
    budget = snapshot.spec.budget
    requested = {d.family for d in snapshot.spec.detectors}
    relation_requested = requested & {"counters", "tokens", "timestamps", "checksums"}
    framing_dependent = requested & {
        "framing",
        "structure",
        "entropy",
        "groups",
        "events",
        "counters",
        "tokens",
        "timestamps",
        "checksums",
    }
    framing_scan_budget = budget.max_scanned_bytes
    framing_budget = budget.max_rule_trials
    if relation_requested and "data_mapping" in requested and framing_dependent:
        framing_budget = max(1, budget.max_rule_trials // 2)
        framing_scan_budget = max(1, budget.max_scanned_bytes * 3 // 4)
    elif relation_requested and framing_dependent:
        framing_budget = max(1, budget.max_rule_trials * 3 // 5)
    elif "data_mapping" in requested and framing_dependent:
        framing_budget = max(1, budget.max_rule_trials * 3 // 4)
        framing_scan_budget = max(1, budget.max_scanned_bytes * 3 // 4)
    scan = Meter(framing_scan_budget)
    trials = Meter(framing_budget)
    evaluations = Meter(budget.max_candidate_evaluations)
    output_meter = Meter(budget.max_evidence_bytes)
    candidates, evidence, diagnostics, units = [], [], [], []
    for capture in snapshot.sources:
        if capture.reconstruction_id is None:
            diagnostics.append(f"capture {capture.id}: no reconstruction; stream extent unknown")
        for failure in capture.reconstruction_failures:
            if failure.included:
                diagnostics.append(
                    f"session {failure.session_id}: {failure.diagnostic}; extent unknown"
                )
    search_ranges = []
    probes = defaultdict(list)
    limited = False
    progress("scan/sample: discovery only", 0, sum(i.stream.extent for i in discovery))
    for item in discovery:
        if cancelled():
            raise WorkCancelled
        source = item.source
        # Initial framing needs a known stream prefix. Never silently restart after a gap.
        run = next(iter(source.known_runs(0)), None)
        if (
            not run
            or run[0] != 0
            or not any(a == 0 for a, _ in selected_ranges(snapshot, item.stream))
        ):
            diagnostics.append(f"stream {item.stream.id}: no known selected prefix; not proposed")
            if item.stream.extent:
                search_ranges.append(
                    SearchRange(
                        anchor=anchor(item.stream, 0, item.stream.extent),
                        scanned=False,
                        diagnostic="no_known_selected_prefix",
                    )
                )
            continue
        end = min(run[1], budget.max_probe_bytes, selected_ranges(snapshot, item.stream)[0][1])
        try:
            data = read_range(source, 0, end, scan)
        except Exhausted:
            limited = True
            diagnostics.append(f"stream {item.stream.id}: max_scanned_bytes; prefix unsearched")
            search_ranges.append(
                SearchRange(
                    anchor=anchor(item.stream, 0, item.stream.extent),
                    scanned=False,
                    diagnostic="max_scanned_bytes",
                )
            )
            continue
        search_ranges.append(
            SearchRange(
                anchor=anchor(item.stream, 0, end), scanned=True, diagnostic="discovery_probe"
            )
        )
        if end < item.stream.extent:
            search_ranges.append(
                SearchRange(
                    anchor=anchor(item.stream, end, item.stream.extent),
                    scanned=False,
                    diagnostic="outside_probe",
                )
            )
        if len(data) >= 2:
            probes[item.stream.direction].append(data)
            limited |= end < source.extent
    framing_results = []
    event_windows_searched = 0
    mapping_trials_searched = 0
    counter_trials_searched = 0
    token_trials_searched = 0
    timestamp_trials_searched = 0
    checksum_trials_searched = 0
    checksum_operations = Meter(budget.max_checksum_operations)
    framed_for_relations = defaultdict(lambda: {"messages": [], "parents": {}, "inputs": {}})
    directions = sorted(probes) if framing_dependent else []
    for index, direction in enumerate(directions):
        progress("framing: bounded rule search", trials.used, trials.maximum)
        remaining_budget = trials.maximum - trials.used
        remaining_directions = len(directions) - index
        direction_trials = Meter(remaining_budget // remaining_directions)
        specs, cut = propose(
            snapshot,
            probes[direction],
            direction,
            direction_trials,
            cancelled,
            lambda done, total: progress("framing: bounded rule search", done, total),
        )
        trials.used += direction_trials.used
        explicit_specs = [f.spec for f in snapshot.framing if f.spec.rule.kind != "manual"]
        if snapshot.interpretation:
            from protocol_lab.interpretation.document import load_model

            model_spec = load_model(snapshot.interpretation.document_json).framing
            if model_spec.rule.kind != "manual":
                explicit_specs.append(model_spec)
        specs = list({content_hash(s): s for s in [*explicit_specs, *specs]}.values())
        limited |= cut
        directional = [i for i in discovery if i.stream.direction == direction]
        for spec in specs:
            rule = FramingCandidateRule(
                kind={
                    "fixed": "fixed_framing",
                    "length": "length_framing",
                    "markers": "marker_framing",
                }[spec.rule.kind],
                framing=spec,
            )
            id = uuid5(run_id, f"{direction}:{content_hash(rule)}")
            checked = check_framing(
                snapshot, id, spec, directional, cancelled, scan, evaluations, output_meter
            )
            limited |= not checked.complete
            constraints = [f for f in snapshot.framing if f.spec.rule.kind == "manual"]
            boundaries = {
                (i.stream.id, a.byte_range.start, a.byte_range.end) for i, a, _ in checked.messages
            }
            scoped_streams = {i.stream.id for i in directional}
            if any(
                (stream_id, interval.start, interval.end) not in boundaries
                for constraint in constraints
                for stream_id in scoped_streams
                if constraint.stream_id in {None, stream_id}
                for interval in constraint.spec.rule.ranges
            ):
                continue
            c = candidate_for(run_id, snapshot, rule, "framing", direction, checked, directional)
            if c.metrics.unique_messages < snapshot.spec.search.min_unique_messages:
                continue
            framing_results.append((c, checked, directional))
    framing_results.sort(key=lambda v: ranking_key(v[0]))
    relation_allowance = max(0, budget.max_rule_trials - trials.used)
    if relation_requested and "data_mapping" in requested:
        relation_allowance //= 2
    relation_trials = Meter(relation_allowance)
    framing_trials_searched = trials.used
    relation_families = sorted(relation_requested)
    relation_meters = {
        family: Meter(
            relation_allowance // len(relation_families)
            + (index < relation_allowance % len(relation_families))
        )
        for index, family in enumerate(relation_families)
    }
    # Both directions receive alternatives; retention is explicit and deterministic.
    cap = min(budget.max_candidates_per_family, budget.max_candidates)
    retained = framing_results[:cap]
    limited |= len(retained) < len(framing_results)
    progress("structure/profile: conditional on frozen framing alternatives", 0, len(retained))
    for c, checked, directional in retained:
        candidates.append(c)
        evidence.extend(checked.evidence)
        for item, a, data in checked.messages:
            units.append(
                SampleUnit(
                    capture_id=item.capture.id,
                    session_id=item.stream.session_id,
                    anchor=a,
                    payload_sha256=hashlib.sha256(data).hexdigest(),
                    data_status="known",
                )
            )
        if requested & {
            "structure",
            "entropy",
            "groups",
            "events",
            "counters",
            "tokens",
            "timestamps",
            "checksums",
        }:
            # Only sampled messages from one explicit framing are compared together.
            per_units = [
                SampleUnit(
                    capture_id=i.capture.id,
                    session_id=i.stream.session_id,
                    anchor=a,
                    payload_sha256=hashlib.sha256(d).hexdigest(),
                    data_status="known",
                )
                for i, a, d in checked.messages
            ]
            selection = select_sample(snapshot.spec, snapshot.sources, per_units, cancelled)
            chosen = {entry.representative.anchor for entry in selection.entries}
            messages = [(i, a, d) for i, a, d in checked.messages if a in chosen]
            if len(messages) < snapshot.spec.search.min_unique_messages:
                continue
            if "tokens" in requested:
                relation_key = content_hash(c.rule.framing)
                framed_for_relations[relation_key]["messages"].extend(messages)
                framed_for_relations[relation_key]["parents"][c.scope.direction] = c
                framed_for_relations[relation_key]["inputs"][c.scope.direction] = directional
            if "structure" in requested:
                for reverse in (False, True):
                    width = min(budget.max_header_bytes, 64, min(len(d) for _, _, d in messages))
                    mask = [
                        len({d[-p - 1] if reverse else d[p] for _, _, d in messages}) == 1
                        for p in range(width)
                    ]
                    pos = 0
                    while pos < width:
                        if not mask[pos]:
                            pos += 1
                            continue
                        end = pos + 1
                        while end < width and mask[end] and end - pos < 64:
                            end += 1
                        data = messages[0][2]
                        value = (
                            data[len(data) - end : len(data) - pos] if reverse else data[pos:end]
                        )
                        kind = (
                            "end_marker"
                            if reverse and pos == 0
                            else "start_marker"
                            if pos == 0
                            else "constant_region"
                        )
                        rule = RegionRule(
                            kind=kind,
                            relative_to="message_end" if reverse else "message_start",
                            offset=pos,
                            length=end - pos,
                            value_hex=value.hex(),
                        )
                        region = make_region(
                            run_id, snapshot, c, rule, messages, directional, output_meter
                        )
                        candidates.append(region[0])
                        evidence.extend(region[1])
                        pos = end
            if "entropy" in requested:
                rule = ProfileRule(
                    kind="entropy_region", measurement="within_block", window_bytes=64
                )
                profile = make_region(
                    run_id, snapshot, c, rule, messages, directional, output_meter
                )
                candidates.append(profile[0])
                evidence.extend(profile[1])
            if "structure" in requested:
                found, found_evidence = propose_delimiters(
                    run_id, snapshot, c, messages, directional, output_meter
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
            if "groups" in requested:
                found, found_evidence = propose_groups(
                    run_id, snapshot, c, messages, directional, output_meter
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
            if "events" in requested:
                found, found_evidence, event_limited, event_windows = propose_events(
                    run_id, snapshot, c, messages, directional, output_meter
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                limited |= event_limited
                event_windows_searched += event_windows
            if "checksums" in requested:
                relation_trials = relation_meters["checksums"]
                from protocol_lab.inference.checksums import propose_checksums

                found, found_evidence, searched, checksum_limited = propose_checksums(
                    run_id,
                    snapshot,
                    c,
                    messages,
                    directional,
                    relation_trials,
                    checksum_operations,
                    output_meter,
                    cancelled,
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                checksum_trials_searched += searched
                limited |= checksum_limited
            if "counters" in requested:
                relation_trials = relation_meters["counters"]
                found, found_evidence, searched = propose_counters(
                    run_id, snapshot, c, messages, directional, relation_trials, output_meter
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                counter_trials_searched += searched
                limited |= relation_trials.used >= relation_trials.maximum
            if "timestamps" in requested:
                relation_trials = relation_meters["timestamps"]
                found, found_evidence, searched = propose_timestamps(
                    run_id, snapshot, c, messages, directional, relation_trials, output_meter
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                timestamp_trials_searched += searched
                limited |= relation_trials.used >= relation_trials.maximum
            if "tokens" in requested:
                found, found_evidence, searched = propose_session_regions(
                    run_id,
                    snapshot,
                    c,
                    messages,
                    directional,
                    relation_meters["tokens"],
                    output_meter,
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                token_trials_searched += searched
                limited |= relation_meters["tokens"].used >= relation_meters["tokens"].maximum
    if "tokens" in requested:
        relation_trials = relation_meters["tokens"]
        for relation in framed_for_relations.values():
            by_direction = defaultdict(list)
            for item, message_anchor, data in relation["messages"]:
                by_direction[item.stream.direction].append((item, message_anchor, data))
            if set(by_direction) != {"a_to_b", "b_to_a"}:
                continue
            parents = relation["parents"]
            parent_ids = tuple(sorted({item.id for item in parents.values()}, key=str))
            for source_direction in ("a_to_b", "b_to_a"):
                parent = parents.get(source_direction)
                if parent is None:
                    continue
                found, found_evidence, searched = propose_copied_values(
                    run_id,
                    snapshot,
                    parent,
                    by_direction,
                    parent_ids,
                    discovery,
                    relation_trials,
                    output_meter,
                    source_direction,
                )
                candidates.extend(found)
                evidence.extend(found_evidence)
                token_trials_searched += searched
                limited |= relation_trials.used >= relation_trials.maximum
    trials.used += sum(meter.used for meter in relation_meters.values())
    if "data_mapping" in requested:
        mapping_trials = Meter(max(0, budget.max_rule_trials - trials.used))
        mapping_scan = Meter(max(0, budget.max_scanned_bytes - scan.used))
        found, found_evidence, mapping_limited = propose_mappings(
            run_id, snapshot, discovery, mapping_scan, mapping_trials, output_meter
        )
        candidates.extend(found)
        evidence.extend(found_evidence)
        limited |= mapping_limited
        mapping_trials_searched = mapping_trials.used
        trials.used += mapping_trials.used
        scan.used += mapping_scan.used
    # Candidate quotas affect completeness, never remove historical evidence from retained rules.
    counts = Counter()
    final = []
    for c in sorted(candidates, key=lambda c: (bool(c.dependency_ids), ranking_key(c))):
        if (
            counts[c.family] >= budget.max_candidates_per_family
            or len(final) >= budget.max_candidates
        ):
            limited = True
            continue
        final.append(c)
        counts[c.family] += 1
    final_ids = {c.id for c in final}
    final = [c for c in final if set(c.dependency_ids) <= final_ids]
    final_ids = {c.id for c in final}
    evidence = [e for e in evidence if e.candidate_id in final_ids]
    # A single snapshot sample records one framing alternative, never overlapping variants.
    units = (
        []
        if not retained
        else [
            SampleUnit(
                capture_id=i.capture.id,
                session_id=i.stream.session_id,
                anchor=a,
                payload_sha256=hashlib.sha256(d).hexdigest(),
                data_status="known",
            )
            for i, a, d in retained[0][1].messages
        ]
    )
    selection = select_sample(snapshot.spec, snapshot.sources, units, cancelled)
    snapshot = snapshot.model_copy(
        update={"sample_anchors": tuple(e.representative.anchor for e in selection.entries)}
    )
    # Coverage is the union of bytes explained by alternatives, not their sum.
    explained = union_size(
        [
            (a.stream_id, a.byte_range.start, a.byte_range.end)
            for c, checked, _ in retained
            if c.id in final_ids
            for _, a, _ in checked.messages
        ]
    )
    if not snapshot.spec.split.holdout_ids:
        diagnostics.append("holdout_unavailable: " + snapshot.spec.split.holdout_unavailable_reason)
    diagnostics.append(
        "Search strategy: signature-guided proposals then finite fixed/length trials; "
        "search_complete refers to this declared strategy, not every possible protocol."
    )
    outcomes = tuple(
        DetectorOutcome(
            family=d.family,
            outcome="unsupported"
            if d.family not in DETECTORS
            else "search_limited"
            if limited
            else "completed"
            if counts[d.family]
            else "insufficient_data",
            searched_units=(
                framing_trials_searched
                if d.family == "framing"
                else event_windows_searched
                if d.family == "events"
                else mapping_trials_searched
                if d.family == "data_mapping"
                else counter_trials_searched
                if d.family == "counters"
                else token_trials_searched
                if d.family == "tokens"
                else timestamp_trials_searched
                if d.family == "timestamps"
                else checksum_trials_searched
                if d.family == "checksums"
                else len(selection.entries)
            ),
            unsearched_units=1 if limited or d.family not in DETECTORS else 0,
            diagnostic="This family is not implemented yet"
            if d.family not in DETECTORS
            else "Bounded search; see ranges and budgets"
            if limited
            else "Declared search completed",
            searched_unit=(
                "rule_trial"
                if d.family in {"framing", "counters", "tokens", "timestamps", "checksums"}
                else "event_message_window"
                if d.family == "events"
                else "mapping_trial"
                if d.family == "data_mapping"
                else "sample_message"
            ),
        )
        for d in snapshot.spec.detectors
    )
    result = InferenceRun(
        id=run_id,
        parent_id=parent_id,
        created_at=datetime.now(UTC),
        snapshot=snapshot,
        outcomes=outcomes,
        search_complete=all(o.outcome in {"completed", "insufficient_data"} for o in outcomes),
        candidate_count=len(final),
        sample_sha256=selection.sha256,
        coverage=actual_coverage(snapshot, inputs, explained),
        diagnostics=tuple(diagnostics),
        rule_trials=trials.used,
        search_ranges=tuple(search_ranges),
    )
    semantic_snapshot = snapshot.model_dump(mode="json")
    # File adapters may create a corpus timestamp per invocation; it is not evidence.
    semantic_snapshot["corpus"].pop("created_at", None)
    semantic = hashlib.sha256(
        json.dumps(
            {
                "snapshot": semantic_snapshot,
                "sample": result.sample_sha256,
                "rules": [
                    (
                        c.rule_sha256,
                        c.scope.direction,
                        c.metrics.model_dump(),
                        c.ranking.model_dump(),
                    )
                    for c in final
                ],
                "outcomes": [o.model_dump() for o in outcomes],
                "evidence": [
                    (
                        next(c.rule_sha256 for c in final if c.id == e.candidate_id),
                        e.model_dump(mode="json", exclude={"candidate_id"}),
                    )
                    for e in evidence
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return result.model_copy(update={"semantic_sha256": semantic}), final, evidence


def union_size(intervals):
    size, last_id, right = 0, None, 0
    for id, a, b in sorted(intervals, key=lambda p: (str(p[0]), p[1], p[2])):
        if id != last_id:
            last_id, right = id, 0
        size += max(0, b - max(a, right))
        right = max(right, b)
    return size


def make_region(run_id, snapshot, parent, rule, messages, inputs, output_meter):
    id = uuid5(run_id, f"{parent.id}:{content_hash(rule)}")
    checked = Checked(evidence=EvidenceList(output_meter))
    for item, a, data in messages:
        if isinstance(rule, RegionRule):
            start = (
                a.byte_range.end - rule.offset - rule.length
                if rule.relative_to == "message_end"
                else a.byte_range.start + rule.offset
            )
            end = start + rule.length
            diagnostic = "constant bytes conditional on framing; width is not established semantics"
        else:
            start, end = (
                a.byte_range.start,
                min(a.byte_range.end, a.byte_range.start + rule.window_bytes),
            )
            block = data[: end - start]
            h = -sum((n / len(block)) * math.log2(n / len(block)) for n in Counter(block).values())
            diagnostic = (
                f"Shannon within block={h:.6f} bits/byte; n={len(block)}; "
                "small-sample biased; neither encryption nor compression is established"
            )
        r = anchor(item.stream, start, end)
        payload = data[start - a.byte_range.start : end - a.byte_range.start]
        checked.messages.append((item, r, payload))
        checked.explained += end - start
        checked.evidence.append(
            CandidateEvidence(
                candidate_id=id,
                status="passed",
                anchor=r,
                sources=tuple(item.provenance(r)),
                diagnostic=diagnostic,
                preview_hex=payload[:64].hex(),
            )
        )
    family = "structure" if isinstance(rule, RegionRule) else "entropy"
    c = candidate_for(
        run_id, snapshot, rule, family, parent.scope.direction, checked, inputs, (parent.id,)
    )
    return c.model_copy(update={"id": id}), checked.evidence


def typed_evaluation(snapshot, candidate, inputs, cancelled, output_meter):
    """Execute A3 relations on the target corpus with their frozen framing rule."""
    rule = candidate.rule
    framing = getattr(rule, "framing", None)
    if framing is None:
        raise ValueError("This analytical rule has no frozen framing rule for evaluation")
    scoped = [
        item
        for item in inputs
        if item.stream.included
        and (
            candidate.scope.direction == "both"
            or item.stream.direction == candidate.scope.direction
        )
    ]
    base = check_framing(
        snapshot,
        candidate.id,
        framing,
        scoped,
        cancelled,
        Meter(snapshot.spec.budget.max_scanned_bytes),
        Meter(snapshot.spec.budget.max_candidate_evaluations),
        Meter(snapshot.spec.budget.max_evidence_bytes),
    )
    evidence = EvidenceList(output_meter)
    statuses = []
    distinct = set()
    unique_messages = len({hashlib.sha256(data).digest() for _, _, data in base.messages})

    def add(status, item, region, diagnostic, preview=""):
        statuses.append(status)
        evidence.append(
            CandidateEvidence(
                candidate_id=candidate.id,
                status=status,
                anchor=region,
                sources=tuple(item.provenance(region)) if item is not None else (),
                diagnostic=diagnostic,
                preview_hex=preview,
            )
        )

    by_stream = defaultdict(list)
    for item, message_anchor, data in base.messages:
        by_stream[item.stream.id].append((item, message_anchor, data))

    if isinstance(rule, ChecksumRule):
        from protocol_lab.inference.checksums import check

        operations = Meter(snapshot.spec.budget.max_checksum_operations)
        for item, message_anchor, data in base.messages:
            if cancelled():
                raise WorkCancelled
            if operations.used + len(data) > operations.maximum:
                base.complete = False
                add("unknown", item, message_anchor, "max_checksum_operations; unsearched")
                continue
            operations.consume(len(data))
            status, diagnostic, region, _ = check(rule, data, cancelled)
            loc = (
                anchor(
                    item.stream,
                    message_anchor.byte_range.start + region[0],
                    message_anchor.byte_range.start + region[1],
                )
                if region
                else message_anchor
            )
            add(status, item, loc, diagnostic)
    elif isinstance(rule, (CounterRule, TimestampRule)):
        from protocol_lab.framing.engine import Piece
        from protocol_lab.inference.compilation import model_draft
        from protocol_lab.interpretation.document import load_model
        from protocol_lab.interpretation.engine import compile_model, parse_message
        from protocol_lab.validation.corpus import CorpusEvaluator
        from protocol_lab.validation.models import ValidationItem

        draft = model_draft(candidate)
        if not draft.compilable:
            raise ValueError("This relational rule cannot be executed as a model")
        model = load_model(draft.document_json)
        parser = compile_model(model)
        relations = CorpusEvaluator(model, candidate.id, cancelled=cancelled)
        owners = {item.stream.id: item for item in scoped}
        # Use the bounded framing pass, then the exact parser and corpus executor
        # used by saved models. Non-message ranges remain prerequisites/barriers.
        for fact in base.evidence:
            if cancelled():
                raise WorkCancelled
            item = owners[fact.anchor.stream_id]
            if fact.status == "passed":
                piece = Piece(
                    id=uuid5(candidate.id, str(fact.anchor)),
                    framing_version=str(candidate.id),
                    kind="message",
                    anchor=fact.anchor,
                    boundary_status="known",
                    data_status="known",
                    diagnostic="",
                )
                parsed = parse_message(
                    model, parser, piece, item.source, cancelled, item.stream.direction
                )
                fields = parsed.fields
                value = next((f for f in fields if f.path == "value"), None)
                if value is not None:
                    distinct.add(int(value.value))
                status, diagnostic = parsed.status, parsed.diagnostic
            else:
                fields = ()
                status = "unknown" if fact.status == "failed" else fact.status
                diagnostic = f"framing dependency: {fact.diagnostic}"
            relations.add(
                ValidationItem(
                    id=uuid5(candidate.id, str(fact.anchor)),
                    capture_id=item.capture.id,
                    session_id=item.stream.session_id,
                    stream_id=item.stream.id,
                    direction=item.stream.direction,
                    anchor=fact.anchor,
                    kind="message" if fact.status == "passed" else "leftover",
                    status=status,
                    diagnostic=diagnostic,
                    fields=fields,
                ),
                message_time_interval(item, fact.anchor),
                item.source,
            )
        for result in relations.finish():
            item = owners.get(result.stream_id)
            region = result.anchor
            # Counter evidence retains both source messages, as before.
            if region is not None and result.related_anchors:
                region = region.model_copy(
                    update={
                        "byte_range": ByteRange(
                            start=min(
                                a.byte_range.start for a in (region, *result.related_anchors)
                            ),
                            end=max(a.byte_range.end for a in (region, *result.related_anchors)),
                        )
                    }
                )
            if result.technical_limit is not None:
                base.complete = False
            add(result.status, item, region, result.diagnostic)

    elif isinstance(rule, RegionRule) and rule.kind in {
        "session_stable_region",
        "session_token_candidate",
    }:
        sessions = defaultdict(list)
        for rows in by_stream.values():
            for item, message_anchor, data in rows:
                sessions[item.stream.session_id].append((item, message_anchor, data))
        session_values = {}
        for session_id, rows in sessions.items():
            values = {
                data[rule.offset : rule.offset + rule.length]
                for _, _, data in rows
                if rule.offset + rule.length <= len(data)
            }
            session_values[session_id] = values
        varied = (
            len({next(iter(values)) for values in session_values.values() if len(values) == 1}) > 1
        )
        for session_id, rows in sessions.items():
            item, message_anchor, data = rows[0]
            if rule.offset + rule.length > len(data):
                add("unknown", item, message_anchor, "region outside framed message")
                continue
            region = anchor(
                item.stream,
                message_anchor.byte_range.start + rule.offset,
                message_anchor.byte_range.start + rule.offset + rule.length,
            )
            values = session_values[session_id]
            if len(values) > 1:
                status = "failed"
            elif not varied or len(session_values) < 2:
                status = "unknown"
            else:
                status = "passed"
            value = data[rule.offset : rule.offset + rule.length]
            distinct.update(values)
            add(
                status,
                item,
                region,
                f"session {session_id}: {len(values)} values across {len(rows)} messages; "
                f"cross-session variation {'observed' if varied else 'not established'}",
                value.hex(),
            )

    elif isinstance(rule, CopyRelationRule):
        source_direction = rule.source_direction
        target_direction = "b_to_a" if source_direction == "a_to_b" else "a_to_b"
        target_by_session = defaultdict(list)
        for item, message_anchor, data in base.messages:
            if (
                item.stream.direction == target_direction
                and rule.target_offset + rule.length <= len(data)
            ):
                interval = message_time_interval(item, message_anchor)
                target_by_session[item.stream.session_id].append(
                    (item, message_anchor, data, interval)
                )
        seen_values = set()
        for item, message_anchor, data in base.messages:
            if item.stream.direction != source_direction:
                continue
            if rule.source_offset + rule.length > len(data):
                add("unknown", item, message_anchor, "source field outside framed message")
                continue
            region = anchor(
                item.stream,
                message_anchor.byte_range.start + rule.source_offset,
                message_anchor.byte_range.start + rule.source_offset + rule.length,
            )
            interval = message_time_interval(item, message_anchor)
            value = data[rule.source_offset : rule.source_offset + rule.length]
            seen_values.add(value)
            if interval is None:
                add(
                    "unknown",
                    item,
                    region,
                    "source packet time unavailable; copy order unknown",
                    value.hex(),
                )
                continue
            targets = target_by_session.get(item.stream.session_id, ())
            if not targets or any(target_time is None for _, _, _, target_time in targets):
                add(
                    "unknown",
                    item,
                    region,
                    "reverse-direction target or packet time unavailable",
                    value.hex(),
                )
                continue
            matched_target = next(
                (
                    target
                    for target in targets
                    if target[2][rule.target_offset : rule.target_offset + rule.length] == value
                    and target[3][0] >= interval[1]
                ),
                None,
            )
            matched = matched_target is not None
            add(
                "passed" if matched else "failed",
                item,
                region,
                "exact value observed later in reverse direction"
                if matched
                else "no later exact copy at the configured target offset",
                value.hex(),
            )
            if matched_target:
                target_item, target_anchor, target_data, _ = matched_target
                target_region = anchor(
                    target_item.stream,
                    target_anchor.byte_range.start + rule.target_offset,
                    target_anchor.byte_range.start + rule.target_offset + rule.length,
                )
                evidence.append(
                    CandidateEvidence(
                        candidate_id=candidate.id,
                        status="passed",
                        anchor=target_region,
                        sources=tuple(target_item.provenance(target_region)),
                        diagnostic=(
                            f"copied value {value.hex()} from source stream "
                            f"{item.stream.id} at offset {region.byte_range.start}"
                        ),
                        preview_hex=target_data[
                            rule.target_offset : rule.target_offset + rule.length
                        ].hex(),
                    )
                )
        distinct.update(seen_values)
    else:
        raise ValueError(f"Typed corpus evaluator does not support {rule.kind}")

    for fact in base.evidence:
        if isinstance(rule, (CounterRule, TimestampRule)) or fact.status == "passed":
            continue
        status = "unknown" if fact.status == "failed" else fact.status
        statuses.append(status)
        evidence.append(
            fact.model_copy(
                update={
                    "candidate_id": candidate.id,
                    "status": status,
                    "diagnostic": f"framing dependency: {fact.diagnostic}",
                }
            )
        )

    # Preserve full-corpus direction/filter accounting from the framing pass.
    considered = {item.stream.id for item in scoped}
    for item in inputs:
        if item.stream.id not in considered and item.stream.extent:
            add(
                "not_applicable",
                item,
                anchor(item.stream, 0, item.stream.extent),
                "outside the frozen candidate scope",
            )
    metrics_value = relation_metrics(
        "transition"
        if isinstance(rule, (CounterRule, CopyRelationRule))
        else "session"
        if isinstance(rule, RegionRule)
        else "message",
        statuses,
        inputs,
        len(distinct),
        unique_messages,
    )
    return base, metrics_value, evidence


def evaluate(
    snapshot,
    candidate,
    inputs,
    discovery_run_id,
    cancelled=lambda: False,
    independence="unverified",
    reason="Independence has not been established",
):
    if snapshot.spec.mode != "evaluate":
        raise ValueError("Evaluation requires mode=evaluate")
    all_inputs = inputs
    inputs = [
        i
        for i in inputs
        if i.stream.included
        and (candidate.scope.direction == "both" or i.stream.direction == candidate.scope.direction)
    ]
    considered = {i.stream.id for i in inputs}
    budget = snapshot.spec.budget
    if isinstance(candidate.rule, FramingCandidateRule):
        checked = check_framing(
            snapshot,
            candidate.id,
            candidate.rule.framing,
            inputs,
            cancelled,
            Meter(budget.max_scanned_bytes),
            Meter(budget.max_candidate_evaluations),
        )
        evidence = checked.evidence
        evaluation_metrics = metrics(checked, inputs)
        for item in all_inputs:
            if item.stream.id not in considered and item.stream.extent:
                evidence.append(
                    CandidateEvidence(
                        candidate_id=candidate.id,
                        status="not_applicable",
                        anchor=anchor(item.stream, 0, item.stream.extent),
                        diagnostic="Outside frozen corpus filters or candidate direction scope",
                    )
                )
    else:
        checked, evaluation_metrics, evidence = typed_evaluation(
            snapshot,
            candidate,
            all_inputs,
            cancelled,
            Meter(budget.max_evidence_bytes),
        )
    record = EvaluationRecord(
        evaluation=CandidateEvaluation(
            id=uuid4(),
            candidate_id=candidate.id,
            rule_sha256=candidate.rule_sha256,
            snapshot=snapshot,
            metrics=evaluation_metrics,
            independence=independence,
            independence_reason=reason,
        ),
        created_at=datetime.now(UTC),
        discovery_run_id=discovery_run_id,
        complete=checked.complete,
        coverage=actual_coverage(snapshot, all_inputs, checked.explained, scope_ids=considered),
        diagnostics=tuple(checked.diagnostics),
        evidence_count=len(evidence),
    )
    return record, evidence
