"""Deterministic metadata-only discovery sampling; holdout bytes are never read here."""

import hashlib
from bisect import bisect_right
from collections import defaultdict, deque
from typing import Literal
from uuid import UUID

from pydantic import Field

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import Record, Sha256, StreamRange
from protocol_lab.inference.models import Count, InferenceSpec, content_hash


def validate_split(spec, sources):
    sources = tuple(sources)
    captures = {source.id: source for source in sources}
    sessions = {
        stream.session_id: source.id
        for source in sources
        for stream in source.streams
        if stream.included
    }
    sessions.update(
        (failure.session_id, source.id)
        for source in sources
        for failure in source.reconstruction_failures
        if failure.included
    )
    split = spec.split
    discovery, holdout = set(split.discovery_ids), set(split.holdout_ids)
    available = set(captures if split.unit == "capture" else sessions)
    if discovery | holdout != available:
        raise ValueError(
            "Split must account for every selected capture/session, without foreign IDs"
        )
    if split.unit == "session":
        discovery = {sessions[s] for s in discovery}
        holdout = {sessions[s] for s in holdout}
    # Separate sessions in one recording are allowed; duplicate *recordings* are not independent.
    if any(a != b and captures[a].sha256 == captures[b].sha256 for a in discovery for b in holdout):
        raise ValueError("Duplicate capture bytes cannot be independent holdout")
    grouped = set()
    for group in spec.recording_groups:
        ids = set(group.capture_ids)
        if not ids <= set(captures) or ids & grouped:
            raise ValueError("Recording groups must be disjoint and refer to selected captures")
        grouped.update(ids)
        if ids & discovery and ids & holdout:
            raise ValueError("The same recording group cannot cross discovery/holdout")


class SampleUnit(Record):
    capture_id: UUID
    session_id: UUID
    anchor: StreamRange
    payload_sha256: Sha256
    data_status: Literal["known", "incomplete", "ambiguous", "mixed"] = "known"


class SampleEntry(Record):
    representative: SampleUnit
    occurrences: tuple[SampleUnit, ...] = Field(min_length=1, max_length=1000000)


class SampleSelection(Record):
    strategy: str = "stratified_hash_round_robin_v1"
    seed: Count
    entries: tuple[SampleEntry, ...]
    discovery_units: Count
    holdout_units: Count
    uncertain_units: Count
    excluded_units: Count
    duplicate_units: Count
    unselected_unique_units: Count
    sha256: Sha256


def select_sample(spec: InferenceSpec, sources, units, cancelled=lambda: False):
    """Stratify capture/session/direction, deduplicate payloads, preserve every occurrence.

    Input is bounded message metadata from an already fixed framing. No payload reader
    or detector is accepted, so holdout content cannot accidentally enter discovery.
    """
    sources = tuple(sources)
    validate_split(spec, sources)
    streams = {
        stream.id: (source.id, stream)
        for source in sources
        for stream in source.streams
        if stream.included
    }
    groups = defaultdict(list)
    exclusions = defaultdict(list)
    for excluded in spec.excluded_ranges:
        _, stream = streams.get(excluded.stream_id, (None, None))
        if stream is None or (
            stream.reconstruction_version != excluded.reconstruction_version
            or excluded.byte_range.end > stream.extent
        ):
            raise ValueError("Excluded range is outside the frozen included stream")
        exclusions[excluded.stream_id].append(excluded.byte_range)
    excluded_intervals = {}
    for stream_id, intervals in exclusions.items():
        merged = []
        for interval in sorted(intervals, key=lambda r: r.start):
            if merged and interval.start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], interval.end))
            else:
                merged.append((interval.start, interval.end))
        excluded_intervals[stream_id] = (merged, [end for _, end in merged])
    seen = set()
    discovery_units = holdout_units = uncertain_units = excluded_units = 0
    for count, unit in enumerate(units, 1):
        if cancelled():
            raise WorkCancelled
        if count > spec.budget.max_sample_units:
            raise ValueError("max_sample_units exceeded; no complete sample published")
        capture, stream = streams.get(unit.anchor.stream_id, (None, None))
        if stream is None or (
            capture != unit.capture_id
            or stream.session_id != unit.session_id
            or stream.reconstruction_version != unit.anchor.reconstruction_version
            or unit.anchor.byte_range.end > stream.extent
        ):
            raise ValueError("Sample unit is outside the frozen included stream")
        identity = (unit.anchor.stream_id, unit.anchor.byte_range.start, unit.anchor.byte_range.end)
        if identity in seen:
            raise ValueError("Duplicate stream range; retransmissions must already be reassembled")
        seen.add(identity)
        partition_id = unit.capture_id if spec.split.unit == "capture" else unit.session_id
        if partition_id in spec.split.holdout_ids:
            holdout_units += 1
            continue
        discovery_units += 1
        intervals, ends = excluded_intervals.get(unit.anchor.stream_id, ([], []))
        index = bisect_right(ends, unit.anchor.byte_range.start)
        if index < len(intervals) and intervals[index][0] < unit.anchor.byte_range.end:
            excluded_units += 1
            continue
        if unit.data_status != "known":
            uncertain_units += 1
            continue
        groups[unit.payload_sha256].append(unit)

    def priority(unit):
        return hashlib.sha256(f"{spec.sampling.seed}:{content_hash(unit)}".encode()).hexdigest()

    buckets = defaultdict(list)
    for occurrences in groups.values():
        if cancelled():
            raise WorkCancelled
        ordered = tuple(sorted(occurrences, key=priority))
        unit = ordered[0]
        direction = streams[unit.anchor.stream_id][1].direction
        buckets[(str(unit.capture_id), str(unit.session_id), direction)].append(
            SampleEntry(representative=unit, occurrences=ordered)
        )
    queues = deque(
        deque(sorted(buckets[key], key=lambda entry: priority(entry.representative)))
        for key in sorted(buckets)
    )
    selected = []
    while queues and len(selected) < spec.budget.max_sample_messages:
        if cancelled():
            raise WorkCancelled
        bucket = queues.popleft()
        selected.append(bucket.popleft())
        if bucket:
            queues.append(bucket)
    # Only semantic data, independent of wall time, traversal order and run UUID.
    fingerprint = hashlib.sha256(
        (spec.sampling.model_dump_json() + "".join(content_hash(e) for e in selected)).encode()
    ).hexdigest()
    return SampleSelection(
        seed=spec.sampling.seed,
        entries=tuple(selected),
        discovery_units=discovery_units,
        holdout_units=holdout_units,
        uncertain_units=uncertain_units,
        excluded_units=excluded_units,
        duplicate_units=sum(len(items) - 1 for items in groups.values()),
        unselected_unique_units=len(groups) - len(selected),
        sha256=fingerprint,
    )
