"""Bounded post-parse relations shared by GUI validation and offline apply."""

import base64
import json
import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from uuid import uuid5

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.diagnostics import technical_limit
from protocol_lab.validation.models import ValidationItem


@dataclass
class Fact:
    item: object
    values: dict
    interval: tuple | None
    raw_values: dict


class PacketTimeIndex:
    def __init__(self, spans, packet_times):
        self.ranges = [
            (span.byte_range.start, span.byte_range.end, packet_times[source.packet_id])
            for span in spans
            for source in span.sources
            if source.packet_id in packet_times
        ]
        self.ends = [right for _, right, _ in self.ranges]

    def get(self, anchor):
        if anchor is None:
            return None
        index = bisect_right(self.ends, anchor.byte_range.start)
        times = []
        while index < len(self.ranges) and self.ranges[index][0] < anchor.byte_range.end:
            times.append(self.ranges[index][2])
            index += 1
        return (min(times), max(times)) if times else None


class CorpusEvaluator:
    def __init__(self, model, run_id, events=(), cancelled=lambda: False):
        self.model, self.run_id, self.events, self.cancelled = model, run_id, events, cancelled
        self.facts, self.omitted, self.first_omitted = [], 0, None
        self.first = None
        self.bytes_used = 0
        self.bytes_omitted, self.first_byte_limited = 0, None
        self.definitions = {}

        def walk(fields, prefix=""):
            for field in fields:
                path = prefix + field.name
                old = self.definitions.get(path)
                self.definitions[path] = field if old is None or old == field else False
                if field.kind == "array":
                    walk(field.fields, path + ".")
                elif field.kind == "switch":
                    for branch in field.cases.values():
                        walk(branch, path + ".")

        walk(model.fields)
        self.paths = {
            path
            for check in model.corpus_checks
            for attr in ("field", "source_field", "target_field", "payload_field")
            if (path := getattr(check, attr, None)) is not None
        }

    def add(self, item, interval=None, source=None):
        self.first = self.first or item
        if not self.model.corpus_checks or item.kind not in {"message", "leftover"}:
            return
        if len(self.facts) >= self.model.max_corpus_units:
            self.omitted += 1
            self.first_omitted = self.first_omitted or item
            return
        fields = tuple(f for f in item.fields if f.path in self.paths)
        values, raw_values = {}, {}
        for field in fields:
            if self.bytes_used + field.length > self.model.max_corpus_bytes:
                self.bytes_omitted += field.length
                self.first_byte_limited = self.first_byte_limited or item
                continue
            self.bytes_used += field.length
            if field.kind == "int":
                values[field.path] = int(field.value)
                definition = self.definitions.get(re.sub(r"\[[0-9]+\]", "", field.path))
                if definition and definition.kind == "int":
                    raw_values[field.path] = int(field.value).to_bytes(
                        field.length, definition.endian, signed=definition.signed
                    )
            elif field.kind in {"bytes", "delimited_bytes"}:
                definition = self.definitions.get(re.sub(r"\[[0-9]+\]", "", field.path))
                if source is not None:
                    if self.cancelled():
                        raise WorkCancelled
                    raw = source.read(field.offset, field.length)
                    if raw is None:
                        continue
                    raw_values[field.path] = raw
                    values[field.path] = (
                        raw[: -len(bytes.fromhex(definition.terminator_hex))]
                        if field.kind == "delimited_bytes"
                        and definition
                        and not definition.include_terminator
                        else raw
                    )
                elif not field.preview_truncated:
                    values[field.path] = bytes.fromhex(field.value)
                    raw_values[field.path] = values[field.path]
                    if (
                        field.kind == "delimited_bytes"
                        and definition
                        and not definition.include_terminator
                    ):
                        raw_values[field.path] += bytes.fromhex(definition.terminator_hex)
        self.facts.append(
            Fact(
                item.model_copy(update={"fields": fields, "unknown_ranges": ()}),
                values,
                interval,
                raw_values,
            )
        )

    def finish(self):
        for check in self.model.corpus_checks:
            if self.cancelled():
                raise WorkCancelled
            results = list(self.execute(check))
            if not results and self.first is not None:
                results.append(
                    (
                        self.first.model_copy(
                            update={
                                "anchor": None,
                                "stream_id": None,
                                "session_id": None,
                                "direction": None,
                            }
                        ),
                        "not_applicable" if self.first.diagnostic == "outside_model_direction_scope" else "unknown",
                        "no eligible parsed messages",
                        (),
                    )
                )
            if self.first_omitted is not None:
                results.append(
                    (
                        self.first_omitted,
                        "unknown",
                        f"max_corpus_units: {self.omitted} additional units unsearched",
                        (),
                    )
                )
            if self.first_byte_limited is not None:
                results.append(
                    (
                        self.first_byte_limited,
                        "unknown",
                        "max_corpus_bytes: additional field bytes unavailable",
                        (),
                    )
                )
            for ordinal, (item, status, diagnostic, related) in enumerate(results):
                yield ValidationItem(
                    id=uuid5(self.run_id, f"corpus:{check.name}:{ordinal}"),
                    capture_id=item.capture_id,
                    session_id=item.session_id,
                    direction=item.direction,
                    stream_id=item.stream_id,
                    anchor=item.anchor,
                    kind="corpus_check",
                    status=status,
                    diagnostic=f"{check.name}/{check.kind}: {diagnostic}",
                    check_name=check.name,
                    check_ordinal=ordinal,
                    related_anchors=related,
                    technical_limit=technical_limit(
                        "max_corpus_bytes",
                        self.bytes_used + self.bytes_omitted,
                        self.model.max_corpus_bytes,
                    )
                    if diagnostic.startswith("max_corpus_bytes")
                    else technical_limit(
                        "max_corpus_units",
                        self.model.max_corpus_units + self.omitted,
                        self.model.max_corpus_units,
                    )
                    if diagnostic.startswith("max_corpus_units")
                    else None,
                )

    def execute(self, check):
        facts = sorted(
            self.facts, key=lambda f: (str(f.item.stream_id), f.item.anchor.byte_range.start)
        )
        previous = {}
        last_clock = {}
        copies, copy_times, copy_maxends, uncertain_sessions = defaultdict(list), {}, {}, set()
        if check.kind == "copied_value":
            for other in facts:
                if other.item.direction == check.source_direction:
                    continue
                value = other.raw_values.get(check.target_field)
                if other.interval is None or value is None or other.item.status != "passed":
                    uncertain_sessions.add(other.item.session_id)
                else:
                    copies[(other.item.session_id, value)].append(other)
            for key, targets in copies.items():
                targets.sort(key=lambda target: target.interval[0])
                copy_times[key] = [target.interval[0] for target in targets]
                ends = []
                for target in targets:
                    ends.append(max(ends[-1], target.interval[1]) if ends else target.interval[1])
                copy_maxends[key] = ends
        events_sorted = sorted(self.events, key=lambda event: int(event.timestamp_ns))
        event_times = [int(event.timestamp_ns) for event in events_sorted]
        event_coverage = [0] * (len(event_times) + 1)
        copy_sessions = {session for session, _ in copies}
        for fact in facts:
            if self.cancelled():
                raise WorkCancelled
            item, values, interval = fact.item, fact.values, fact.interval
            if item.status == "not_applicable":
                yield item, "not_applicable", "outside applicable model/rule scope", ()
                continue
            if item.kind != "message" or item.status != "passed":
                previous.pop(item.stream_id, None)
                yield item, "unknown", "message or framing prerequisite incomplete", ()
                continue
            if check.kind == "counter":
                old = previous.get(item.stream_id)
                previous[item.stream_id] = fact
                field = next((f for f in item.fields if f.path == check.field), None)
                value = values.get(check.field)
                if old is None or field is None or not isinstance(value, int):
                    yield item, "unknown", "no usable preceding message/field", ()
                    continue
                before = old.values.get(check.field)
                if (
                    not isinstance(before, int)
                    or old.item.anchor.byte_range.end != item.anchor.byte_range.start
                ):
                    yield item, "unknown", "unobserved transition or preceding field", ()
                    continue
                step = check.increment
                if check.step == "message_length":
                    step *= old.item.anchor.byte_range.end - old.item.anchor.byte_range.start
                elif check.step == "payload_length":
                    payload = next(
                        (f for f in old.item.fields if f.path == check.payload_field), None
                    )
                    if payload is None:
                        yield item, "unknown", "payload field unavailable", ()
                        continue
                    step *= payload.length
                expected = before + step
                if check.wrap:
                    modulus = 1 << (field.length * 8)
                    minimum = -(modulus // 2) if before < 0 or value < 0 else 0
                    expected = (expected - minimum) % modulus + minimum
                yield (
                    item,
                    "passed" if value == expected else "failed",
                    (f"expected={expected}, observed={value}"),
                    (old.item.anchor,),
                )
            elif check.kind == "timestamp":
                value = values.get(check.field)
                if not isinstance(value, int) or interval is None:
                    yield item, "unknown", "integer field or packet timestamps unavailable", ()
                    continue
                prior_clock = last_clock.get(item.stream_id)
                last_clock[item.stream_id] = interval
                if prior_clock is not None and interval[1] < prior_clock[0]:
                    yield item, "unknown", "capture_clock_nonmonotonic; clock prerequisite uncertain", ()
                    continue
                scale = {"s": 10**9, "ms": 10**6, "us": 1000, "ns": 1}[check.unit]
                if check.epoch == "session_relative":
                    first = previous.setdefault(item.stream_id, fact)
                    first_value = first.values.get(check.field)
                    if first is fact or not isinstance(first_value, int) or first.interval is None:
                        yield (
                            item,
                            "unknown",
                            "observed stream baseline; elapsed interval unavailable",
                            (),
                        )
                        continue
                    predicted = (value - first_value) * scale
                    predicted += predicted * check.drift_ppm // 1000000
                    predicted += int(check.clock_offset_ns)
                    low, high = interval[0] - first.interval[1], interval[1] - first.interval[0]
                else:
                    raw_ns = value * scale
                    predicted = (
                        raw_ns
                        + ((raw_ns - int(check.reference_ns)) * check.drift_ppm // 1000000)
                        + int(check.clock_offset_ns)
                    )
                    low, high = interval
                status = (
                    "passed"
                    if low - check.tolerance_ns <= predicted <= high + check.tolerance_ns
                    else "failed"
                )
                yield item, status, f"predicted_ns={predicted}; packet_interval=[{low},{high}]", ()
            elif check.kind == "copied_value":
                if item.direction != check.source_direction:
                    yield item, "not_applicable", "reverse-direction target message", ()
                    continue
                value = fact.raw_values.get(check.source_field)
                key = (item.session_id, value)
                if value is None or interval is None:
                    yield (
                        item,
                        "unknown",
                        "source, reverse direction or packet-time prerequisite missing",
                        (),
                    )
                    continue
                targets = copies.get(key, ())
                index = bisect_right(copy_times.get(key, ()), interval[1])
                matched = targets[index] if index < len(targets) else None
                overlapping = index > 0 and copy_maxends[key][index - 1] >= interval[0]
                unknown = (
                    item.session_id in uncertain_sessions or item.session_id not in copy_sessions
                )
                yield (
                    item,
                    "passed" if matched else "ambiguous" if overlapping else "unknown" if unknown else "failed",
                    ("exact later copy" if matched else "no established later copy"),
                    (matched.item.anchor,) if matched else (),
                )
            elif check.kind in {"event_association", "parameter_mapping"}:
                if not self.events or interval is None:
                    yield item, "unknown", "frozen action log or packet timestamps unavailable", ()
                    continue
                left = bisect_left(event_times, interval[0] - getattr(check, "after_ns", 10**9))
                right = bisect_right(event_times, interval[1] + getattr(check, "before_ns", 0))
                events = events_sorted[left : min(right, left + 2)]
                if right > left:
                    event_coverage[left] += 1
                    event_coverage[right] -= 1
                if len(events) != 1:
                    yield (
                        item,
                        "ambiguous" if len(events) > 1 else "not_applicable",
                        (
                            "overlapping action windows"
                            if events
                            else "outside selected action windows"
                        ),
                        (),
                    )
                    continue
                if check.kind == "event_association":
                    yield item, "passed", f"event={events[0].id}; temporal association", ()
                    continue
                parameter = json.loads(events[0].parameters_json, parse_float=Decimal)
                try:
                    for key in check.parameter_path:
                        parameter = parameter[key]
                    if check.encoding == "integer":
                        if (
                            isinstance(parameter, bool)
                            or isinstance(parameter, float)
                            or (
                                isinstance(parameter, Decimal)
                                and parameter != parameter.to_integral_value()
                            )
                        ):
                            raise ValueError("Nonintegral parameter")
                        encoded = int(parameter).to_bytes(
                            check.width, check.endian, signed=check.signed
                        )
                    else:
                        encoded = str(parameter).encode(
                            "ascii" if check.encoding == "decimal" else check.encoding
                        )
                        if check.bom:
                            encoded = (
                                b"\xff\xfe" if check.encoding == "utf-16le" else b"\xfe\xff"
                            ) + encoded
                    if check.base64 != "none":
                        encoded = (
                            base64.b64encode
                            if check.base64 == "standard"
                            else base64.urlsafe_b64encode
                        )(encoded)
                        if not check.padding:
                            encoded = encoded.rstrip(b"=")
                except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
                    yield item, "unknown", "parameter path/representation unavailable", ()
                    continue
                actual = values.get(check.field)
                if isinstance(actual, int) and check.encoding != "integer":
                    actual = fact.raw_values.get(check.field)
                if (
                    isinstance(actual, int)
                    and check.encoding == "integer"
                    and check.base64 == "none"
                ):
                    expected = int.from_bytes(encoded, check.endian, signed=check.signed)
                else:
                    expected = encoded
                yield (
                    item,
                    "unknown" if actual is None else "passed" if actual == expected else "failed",
                    (f"event={events[0].id}; explicit parameter representation compared"),
                    (),
                )
        if check.kind in {"event_association", "parameter_mapping"} and self.first is not None:
            covered = 0
            for index, event in enumerate(events_sorted):
                covered += event_coverage[index]
                if covered == 0:
                    yield (
                        self.first.model_copy(
                            update={
                                "anchor": None,
                                "stream_id": None,
                                "session_id": None,
                                "direction": None,
                            }
                        ),
                        "unknown",
                        f"event={event.id}: no timestamped message in its window",
                        (),
                    )
