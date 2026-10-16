"""Shared streaming corpus execution and comparison, without database/HTTP imports."""

import hashlib
import json
from collections import Counter
from uuid import uuid5

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.domain.models import ByteRange, StreamRange
from protocol_lab.framing.engine import frame
from protocol_lab.interpretation.engine import UnknownRange, compile_model, parse_message
from protocol_lab.validation.models import (
    STATUSES,
    Coverage,
    Difference,
    ReconstructionFailure,
    ValidationItem,
)


def matches_session(spec, session, start_ns, end_ns):
    if spec.address is not None and str(spec.address) not in {
        str(session.endpoint_a.address),
        str(session.endpoint_b.address),
    }:
        return False
    if spec.port is not None and spec.port not in {
        session.endpoint_a.port,
        session.endpoint_b.port,
    }:
        return False
    if spec.start_ns is not None and (end_ns is None or int(end_ns) < int(spec.start_ns)):
        return False
    if spec.end_ns is not None and (start_ns is None or int(start_ns) > int(spec.end_ns)):
        return False
    return True


def item_id(run_id, capture_id, anchor, kind, stream_id=None, session_id=None, direction=None):
    if anchor:
        token = f"{capture_id}:{anchor.stream_id}:{anchor.byte_range.start}:{anchor.byte_range.end}"
    elif kind == "reconstruction_diagnostic":
        token = f"{capture_id}:{session_id}:{direction}"
    else:
        token = f"{capture_id}:{stream_id or ''}"
    return uuid5(run_id, f"{token}:{kind}")


def reconstruction_failures(session, included=True, direction="both"):
    available = {stream.direction for stream in session.streams}
    return tuple(
        ReconstructionFailure(
            session_id=session.id,
            direction=missing,
            included=included and direction in {"both", missing},
            diagnostic="; ".join(
                issue for issue in session.diagnostics if issue.startswith(f"{missing}:")
            )
            or f"{missing}:direction_unavailable",
        )
        for missing in ("a_to_b", "b_to_a")
        if missing not in available
    )


def reconstruction_diagnostics(run_id, capture):
    for failure in capture.reconstruction_failures:
        yield ValidationItem(
            id=item_id(
                run_id,
                capture.id,
                None,
                "reconstruction_diagnostic",
                session_id=failure.session_id,
                direction=failure.direction,
            ),
            capture_id=capture.id,
            session_id=failure.session_id,
            direction=failure.direction,
            kind="reconstruction_diagnostic",
            status="unknown" if failure.included else "not_applicable",
            diagnostic=(
                "reconstruction_failed:" if failure.included else "excluded_by_corpus_filters:"
            )
            + failure.diagnostic
            + "; stream extent unknown",
        )


def values_hash(fields):
    return hashlib.sha256(
        json.dumps(
            [f.model_dump(mode="json") for f in fields], sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def capture_diagnostics(run_id, capture):
    if not capture.reconstruction_id:
        yield ValidationItem(
            id=item_id(run_id, capture.id, None, "capture_diagnostic"),
            capture_id=capture.id,
            kind="capture_diagnostic",
            status="unknown",
            diagnostic="capture_has_no_completed_reconstruction; stream extent unknown",
        )
    elif (
        not capture.streams and not capture.reconstruction_failures
    ) or capture.eligible_packets < capture.packet_count:
        uncertain = bool(set(capture.diagnostics) - {"non_tcp"}) or (
            not capture.streams and capture.eligible_packets > 0
        )
        yield ValidationItem(
            id=item_id(run_id, capture.id, None, "capture_diagnostic"),
            capture_id=capture.id,
            kind="capture_diagnostic",
            status="unknown" if uncertain else "not_applicable",
            diagnostic=f"noneligible_packets:{capture.packet_count - capture.eligible_packets}; "
            "see capture diagnostics; no application bytes inferred",
        )


def validate_stream(
    run_id,
    capture,
    stream,
    source,
    model,
    cancelled=lambda: False,
    progress=lambda done, total: None,
):
    if cancelled():
        raise WorkCancelled
    anchor = (
        StreamRange(
            stream_id=stream.id,
            reconstruction_version=stream.reconstruction_version,
            byte_range=ByteRange(start=0, end=stream.extent),
        )
        if stream.extent
        else None
    )
    if not stream.included or not stream.extent:
        kind = "excluded" if not stream.included else "stream_diagnostic"
        yield ValidationItem(
            id=item_id(run_id, capture.id, anchor, kind, stream.id),
            capture_id=capture.id,
            session_id=stream.session_id,
            stream_id=stream.id,
            direction=stream.direction,
            anchor=anchor,
            kind=kind,
            status="not_applicable",
            diagnostic="excluded_by_corpus_filters"
            if not stream.included
            else "empty_directed_stream",
        )
        return
    if model.direction not in {"both", stream.direction}:
        yield ValidationItem(
            id=item_id(run_id, capture.id, anchor, "stream_diagnostic"),
            capture_id=capture.id,
            session_id=stream.session_id,
            stream_id=stream.id,
            direction=stream.direction,
            anchor=anchor,
            kind="stream_diagnostic",
            status="not_applicable",
            diagnostic="outside_model_direction_scope",
        )
        return
    try:
        framed = frame(
            stream.id,
            stream.reconstruction_version,
            capture.id,
            capture.sha256,
            source,
            model.framing,
            cancelled,
            lambda done, total: progress(done, total * 2),
        )
    except ValueError as exc:
        yield ValidationItem(
            id=item_id(run_id, capture.id, anchor, "stream_diagnostic"),
            capture_id=capture.id,
            session_id=stream.session_id,
            stream_id=stream.id,
            direction=stream.direction,
            anchor=anchor,
            kind="stream_diagnostic",
            status="unknown",
            diagnostic=f"framing_failed:{exc}",
        )
        return
    parser = compile_model(model)
    for piece in framed.pieces:
        if cancelled():
            raise WorkCancelled
        limit = piece.technical_limit
        try:
            result = parse_message(model, parser, piece, source, cancelled, stream.direction)
            fields, unknown, status, diagnostic = (
                result.fields,
                result.unknown_ranges,
                result.status,
                result.diagnostic,
            )
            limit = result.technical_limit
            if piece.kind == "leftover":
                status = "ambiguous" if piece.data_status in {"ambiguous", "mixed"} else "unknown"
                diagnostic = f"unframed:{piece.diagnostic}"
        except ValueError as exc:
            fields, status, diagnostic = (), "unknown", f"decode_limit:{exc}"
            unknown = (UnknownRange(anchor=piece.anchor, reason="resource_limit"),)
        progress(stream.extent + piece.anchor.byte_range.end, stream.extent * 2)
        yield ValidationItem(
            id=item_id(run_id, capture.id, piece.anchor, piece.kind),
            capture_id=capture.id,
            session_id=stream.session_id,
            stream_id=stream.id,
            anchor=piece.anchor,
            framing_version=str(framed.id),
            direction=stream.direction,
            kind=piece.kind,
            status=status,
            diagnostic=diagnostic,
            fields=fields,
            unknown_ranges=unknown,
            technical_limit=limit,
        )


class CoverageCounter:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.counts, self.messages, self.bytes = Counter(), Counter(), Counter()
        self.unframed = self.undecoded = self.decoded = 0
        self.relations = Counter()

    def add(self, item):
        self.counts[item.status] += 1
        if item.kind == "corpus_check":
            self.relations[item.status] += 1
            return
        if item.kind == "message":
            self.messages[item.status] += 1
        length = item.anchor.byte_range.end - item.anchor.byte_range.start if item.anchor else 0
        self.bytes[item.status] += length
        if item.kind == "leftover":
            self.unframed += length
        if item.kind not in {"excluded", "capture_diagnostic"}:
            self.undecoded += sum(
                u.anchor.byte_range.end - u.anchor.byte_range.start for u in item.unknown_ranges
            )
            if item.kind == "stream_diagnostic" and item.status == "unknown":
                self.undecoded += length
        self.decoded += sum(
            f.length for f in item.fields if f.kind in {"int", "bytes", "delimited_bytes"}
        )

    def result(self):
        sources = self.snapshot.sources
        stream_bytes = sum(s.extent for c in sources for s in c.streams)
        selected = sum(s.extent for c in sources for s in c.streams if s.included)
        return Coverage(
            counts={s: self.counts[s] for s in STATUSES},
            corpus_check_counts={s: self.relations[s] for s in STATUSES},
            message_counts={s: self.messages[s] for s in STATUSES},
            byte_counts={s: self.bytes[s] for s in STATUSES},
            stream_bytes=stream_bytes,
            selected_stream_bytes=selected,
            excluded_stream_bytes=stream_bytes - selected,
            unframed_bytes=self.unframed,
            undecoded_bytes=self.undecoded,
            decoded_leaf_bytes=self.decoded,
            captures=len(sources),
            captures_without_reconstruction=sum(c.reconstruction_id is None for c in sources),
            packets=sum(c.packet_count for c in sources),
            noneligible_packets=sum(c.packet_count - c.eligible_packets for c in sources),
            unavailable_source_bytes=sum(
                s.data_status_bytes.get("gap", 0) + s.data_status_bytes.get("truncated", 0)
                for c in sources
                for s in c.streams
                if s.included
            ),
            ambiguous_source_bytes=sum(
                s.data_status_bytes.get("ambiguous", 0)
                for c in sources
                for s in c.streams
                if s.included
            ),
            unreconstructed_directions=sum(
                failure.included
                for c in sources
                for failure in getattr(c, "reconstruction_failures", ())
            ),
            excluded_unreconstructed_directions=sum(
                not failure.included
                for c in sources
                for failure in getattr(c, "reconstruction_failures", ())
            ),
        )


def range_key(item):
    r = item.anchor
    return (
        str(item.capture_id),
        str(item.stream_id) if item.stream_id else "",
        r.reconstruction_version if r else "",
        r.byte_range.start if r else -1,
        r.byte_range.end if r else -1,
        item.kind,
        str(item.session_id) if item.kind == "reconstruction_diagnostic" else "",
        item.direction or "",
        item.check_name or "",
        item.check_ordinal,
    )


def compare(left, right):
    """Merge sorted exact source-range keys. Reframed ranges remain added/removed, never guessed."""
    a, b = next(left, None), next(right, None)
    while a is not None or b is not None:
        if b is None or (a is not None and range_key(a) < range_key(b)):
            yield Difference(left=a, right=None, change="removed")
            a = next(left, None)
        elif a is None or range_key(b) < range_key(a):
            yield Difference(left=None, right=b, change="added")
            b = next(right, None)
        else:
            change = (
                "status"
                if a.status != b.status
                else "values"
                if a.values_sha256 != b.values_sha256
                else "diagnostic"
                if a.diagnostic != b.diagnostic or a.technical_limit != b.technical_limit
                else None
            )
            if change:
                yield Difference(left=a, right=b, change=change)
            a, b = next(left, None), next(right, None)
