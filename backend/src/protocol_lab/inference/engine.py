"""Bounded offline proposals. Screening never issues Passed; shared frame() does.

Discovery reads no holdout bytes. All retained framing rules are frozen before
evaluation, which preserves leftovers, source uncertainty and unsearched ranges.
"""

import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    DetectorOutcome,
    FramingCandidateRule,
    InferenceCandidate,
    InferenceCoverage,
    InferenceMetrics,
    InferenceRun,
    ProfileRule,
    RankingComponents,
    RegionRule,
    SearchRange,
    content_hash,
)
from protocol_lab.inference.ranking import ranking_key
from protocol_lab.inference.results import EvaluationRecord
from protocol_lab.inference.sampling import SampleUnit, select_sample

VERSION = "inference-v1"
DETECTORS = {
    "framing": "bounded-framing-1",
    "structure": "common-regions-1",
    "entropy": "profile-1",
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
        trials.consume()
        if trials.used % 256 == 0:
            progress(trials.used, trials.maximum)
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
            else (lengths > 1, sum(map(len, messages)),
                  Fraction(independent, min(map(len, messages))),
                  -Fraction(sum(map(len, messages)), len(messages)), -start)
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
    if snapshot.spec.logs or snapshot.spec.parameters:
        raise ValueError("Logs and parameter detectors require A2; no input is silently ignored")
    run_id = run_id or uuid4()
    inputs = sorted(inputs, key=lambda i: str(i.stream.id))
    discovery = partition(snapshot, inputs, "discovery")
    budget = snapshot.spec.budget
    scan = Meter(budget.max_scanned_bytes)
    trials = Meter(budget.max_rule_trials)
    evaluations = Meter(budget.max_candidate_evaluations)
    output_meter = Meter(budget.max_evidence_bytes)
    requested = {d.family for d in snapshot.spec.detectors}
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
    for direction in sorted(probes):
        progress("framing: bounded rule search", trials.used, trials.maximum)
        direction_trials = Meter(max(1, budget.max_rule_trials // max(1, len(probes))))
        specs, cut = propose(snapshot, probes[direction], direction, direction_trials, cancelled,
                             lambda done, total: progress("framing: bounded rule search", done, total))
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
        if "structure" in requested or "entropy" in requested:
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
            searched_units=trials.used if d.family == "framing" else len(selection.entries),
            unsearched_units=1 if limited or d.family not in DETECTORS else 0,
            diagnostic="No implementation for this family in A1"
            if d.family not in DETECTORS
            else "Bounded search; see ranges and budgets"
            if limited
            else "Declared search completed",
            searched_unit="rule_trial" if d.family == "framing" else "sample_message",
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


def evaluate(
    snapshot,
    candidate,
    inputs,
    discovery_run_id,
    cancelled=lambda: False,
    independence="unverified",
    reason="Independence has not been established",
):
    if snapshot.spec.mode != "evaluate" or not isinstance(candidate.rule, FramingCandidateRule):
        raise ValueError("A1 evaluates frozen framing candidates only")
    all_inputs = inputs
    inputs = [
        i
        for i in inputs
        if i.stream.included
        and (candidate.scope.direction == "both" or i.stream.direction == candidate.scope.direction)
    ]
    budget = snapshot.spec.budget
    checked = check_framing(
        snapshot,
        candidate.id,
        candidate.rule.framing,
        inputs,
        cancelled,
        Meter(budget.max_scanned_bytes),
        Meter(budget.max_candidate_evaluations),
    )
    considered = {i.stream.id for i in inputs}
    for item in all_inputs:
        if item.stream.id not in considered and item.stream.extent:
            checked.evidence.append(
                CandidateEvidence(
                    candidate_id=candidate.id,
                    status="not_applicable",
                    anchor=anchor(item.stream, 0, item.stream.extent),
                    diagnostic="Outside frozen corpus filters or candidate direction scope",
                )
            )
    record = EvaluationRecord(
        evaluation=CandidateEvaluation(
            id=uuid4(),
            candidate_id=candidate.id,
            rule_sha256=candidate.rule_sha256,
            snapshot=snapshot,
            metrics=metrics(checked, inputs),
            independence=independence,
            independence_reason=reason,
        ),
        created_at=datetime.now(UTC),
        discovery_run_id=discovery_run_id,
        complete=checked.complete,
        coverage=actual_coverage(snapshot, all_inputs, checked.explained, scope_ids=considered),
        diagnostics=tuple(checked.diagnostics),
        evidence_count=len(checked.evidence),
    )
    return record, checked.evidence
