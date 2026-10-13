"""TCP evidence reconstruction. No HTTP, database, framing or semantic inference."""

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID, uuid5

from pydantic import Field

from protocol_lab.capture.index import IndexedPacket, WorkCancelled
from protocol_lab.domain.models import (
    ByteRange,
    DirectedStream,
    Endpoint,
    Record,
    Session,
    SourceRange,
    StreamIssue,
    StreamRange,
)

VERSION = "tcp-v1"
POLICY = "retain-all-overlaps"
MOD = 1 << 32
HALF = MOD // 2


class ReconstructionError(ValueError):
    pass


class ReconstructionSettings(Record):
    # Resource protection, not a protocol length restriction.
    max_sessions: int = Field(default=10000, ge=1)
    max_spans_per_stream: int = Field(default=1000000, ge=1)
    max_comparison_bytes: int = Field(default=256 * 1024 * 1024, ge=1)


class Evidence(SourceRange):
    packet_index: int
    file_offset: int  # Absolute source offset at the beginning of this range.
    packet_offset: int  # Relative to captured frame, including link/IP/TCP headers.


class Span(Record):
    byte_range: ByteRange
    status: Literal["known", "ambiguous", "gap", "truncated"]
    sources: tuple[Evidence, ...] = ()


class RebuiltStream(DirectedStream):
    spans: tuple[Span, ...] = ()


class RebuiltSession(Session):
    section_index: int
    interface_id: int
    packet_ids: tuple[UUID, ...]
    closed: bool
    streams: tuple[RebuiltStream, ...]


class Reconstruction(Record):
    capture_id: UUID
    version: str = VERSION
    policy: str = POLICY
    settings: ReconstructionSettings
    sessions: tuple[RebuiltSession, ...]
    excluded_packet_ids: tuple[UUID, ...]


@dataclass
class Connection:
    packets: list[IndexedPacket]
    a: tuple[str, int]
    b: tuple[str, int]
    syn: dict = field(default_factory=dict)
    fin: set = field(default_factory=set)
    fin_sequence: dict = field(default_factory=dict)
    closed: bool = False
    start_known: bool = False
    roles_known: bool = False
    issues: list[str] = field(default_factory=list)


def endpoint(packet):
    return (packet.source_ip, packet.source_port), (packet.destination_ip, packet.destination_port)


def sessionize(packets, settings, cancelled):
    active = {}
    connections = []
    excluded = []
    for packet in packets:
        if cancelled():
            raise WorkCancelled
        if not packet.eligible_for_reassembly:
            excluded.append(packet.id)
            continue
        src, dst = endpoint(packet)
        # Network interfaces / PCAPNG sections are separate observation domains.
        key = (packet.section_index, packet.interface_id, *sorted((src, dst)))
        previous = active.get(key)
        flags = packet.tcp_flags or 0
        syn = bool(flags & 2)
        bare_syn = syn and not flags & 16
        new_syn = (
            bare_syn
            and previous
            and (
                previous.closed
                or (src in previous.syn and previous.syn[src] != packet.tcp_sequence)
                or (not previous.syn)
            )
        )
        # A retransmitted final FIN/RST still belongs to the closed connection.
        terminal_repeat = previous and any(
            endpoint(p)[0] == src
            and p.tcp_sequence == packet.tcp_sequence
            and p.tcp_flags == flags
            and p.payload_length == packet.payload_length
            for p in previous.packets[-4:]
        )
        late_before_fin = False
        if (
            previous
            and previous.closed
            and packet.declared_payload_length
            and not syn
            and src in previous.fin_sequence
        ):
            start = (packet.tcp_sequence + bool(flags & 2)) % MOD
            to_fin = (previous.fin_sequence[src] - start) % MOD
            from_syn = (start - previous.syn[src] - 1) % MOD if src in previous.syn else 0
            late_before_fin = packet.declared_payload_length <= to_fin < HALF and from_syn < HALF
        if (
            previous is None
            or new_syn
            or (
                previous.closed
                and not terminal_repeat
                and not late_before_fin
                and (packet.declared_payload_length or syn)
            )
        ):
            if len(connections) >= settings.max_sessions:
                raise ReconstructionError(
                    "Reconstruction exceeds max_sessions; no result published"
                )
            previous = Connection([], src, dst)
            previous.start_known = bare_syn
            previous.roles_known = bare_syn
            if not bare_syn:
                previous.issues += [
                    "connection_start_unavailable",
                    "endpoint_roles_unknown",
                    "connection_identity_uncertain_without_syn",
                ]
            if new_syn and not active[key].closed:
                previous.issues.append("new_syn_before_previous_close")
                active[key].issues.append("connection_end_unavailable")
            active[key] = previous
            connections.append(previous)
        if bare_syn and src not in previous.syn and previous.syn:
            if not previous.start_known and all(
                (p.tcp_flags or 0) & 18 == 18 for p in previous.packets
            ):
                previous.a, previous.b = src, dst
                previous.start_known = previous.roles_known = True
                previous.issues = [
                    issue
                    for issue in previous.issues
                    if issue
                    not in (
                        "connection_start_unavailable",
                        "endpoint_roles_unknown",
                        "syn_ack_without_initial_syn",
                        "connection_identity_uncertain_without_syn",
                    )
                ]
            else:
                previous.roles_known = False
                previous.issues.append("simultaneous_open_roles_unknown")
        if syn:
            previous.syn[src] = packet.tcp_sequence
            if not bare_syn and not previous.start_known:
                previous.issues.append("syn_ack_without_initial_syn")
        if late_before_fin and not terminal_repeat:
            previous.issues.append("post_close_payload_identity_uncertain")
        if flags & 1:
            previous.fin.add(src)
            previous.fin_sequence[src] = (
                packet.tcp_sequence + bool(flags & 2) + packet.declared_payload_length
            ) % MOD
        if flags & 4 or len(previous.fin) == 2:
            previous.closed = True
        previous.packets.append(packet)
    return connections, excluded


@dataclass
class Segment:
    packet: IndexedPacket
    start: int
    data: bytes
    declared: int


def unwrap(value: int, reference: int) -> int:
    delta = (value - reference) % MOD
    if delta == HALF:
        raise ValueError("sequence_distance_ambiguous")
    return reference + (delta if delta < HALF else delta - MOD)


def rebuild_stream(connection, session_id, direction, source, settings, cancelled):
    sender = connection.a if direction == "a_to_b" else connection.b
    packets = [p for p in connection.packets if endpoint(p)[0] == sender]
    stream_id = uuid5(session_id, direction + VERSION)
    segments = []
    reference = None
    syn_origin = None
    ends = []
    for packet in packets:
        if cancelled():
            raise WorkCancelled
        sequence = packet.tcp_sequence
        position = sequence if reference is None else unwrap(sequence, reference)
        flags = packet.tcp_flags or 0
        start = position + bool(flags & 2)
        if flags & 2:
            if syn_origin is not None and syn_origin != start:
                raise ValueError("conflicting_syn_sequence")
            syn_origin = start if syn_origin is None else syn_origin
        declared = packet.declared_payload_length
        # ACK-only sequence numbers do not establish byte coverage or length.
        if declared or flags & 1:
            ends.append(start + declared)
        if declared:
            data = source(packet)
            if len(data) != packet.payload_length:
                raise ValueError("source_payload_length_mismatch")
            segments.append(Segment(packet, start, data, declared))
        reference = max(reference if reference is not None else position, start + declared)
    origin = (
        syn_origin
        if syn_origin is not None
        else min((s.start for s in segments), default=min(ends, default=0))
    )
    if any(s.start < origin for s in segments):
        raise ValueError("payload_before_syn_origin")
    extent = max(ends, default=origin) - origin
    if extent < 0 or extent >= HALF:
        raise ValueError("sequence_extent_ambiguous")
    boundaries = {origin, origin + extent}
    events = defaultdict(lambda: [[], [], [], []])
    for index, segment in enumerate(segments):
        boundaries.update(
            (segment.start, segment.start + len(segment.data), segment.start + segment.declared)
        )
        if segment.data:
            events[segment.start][0].append(index)
            events[segment.start + len(segment.data)][1].append(index)
        if len(segment.data) < segment.declared:
            events[segment.start + len(segment.data)][2].append(index)
            events[segment.start + segment.declared][3].append(index)
    ordered = sorted(boundaries)
    active = set()
    truncated_segments = set()
    spans = []
    comparisons = 0

    def append(start, end, status, contributors):
        if end <= start:
            return
        if len(spans) >= settings.max_spans_per_stream:
            raise ValueError("max_spans_per_stream_exceeded")
        interval = ByteRange(start=start - origin, end=end - origin)
        evidence = []
        for index in sorted(contributors):
            segment = segments[index]
            packet = segment.packet
            relative = start - segment.start
            evidence.append(
                Evidence(
                    capture_id=packet.capture_id,
                    packet_id=packet.id,
                    packet_index=packet.index,
                    packet_payload_range=ByteRange(start=relative, end=relative + end - start),
                    stream=StreamRange(
                        stream_id=stream_id, reconstruction_version=VERSION, byte_range=interval
                    ),
                    file_offset=packet.file_offset + packet.payload_offset + relative,
                    packet_offset=packet.payload_offset + relative,
                )
            )
        spans.append(Span(byte_range=interval, status=status, sources=tuple(evidence)))

    for left, right in zip(ordered, ordered[1:], strict=False):
        if cancelled():
            raise WorkCancelled
        active.difference_update(events[left][1])
        active.update(events[left][0])
        truncated_segments.difference_update(events[left][3])
        truncated_segments.update(events[left][2])
        if not active:
            append(left, right, "truncated" if truncated_segments else "gap", ())
            continue
        contributors = sorted(active)
        first = segments[contributors[0]]
        if len(contributors) == 1:
            append(left, right, "known", contributors)
            continue
        comparisons += (right - left) * len(contributors)
        if comparisons > settings.max_comparison_bytes:
            raise ValueError("max_comparison_bytes_exceeded")
        # Split equal/conflicting runs; never pick a hidden winning retransmission.
        run_start = left
        last_status = None
        for position in range(left, right):
            if position % 4096 == 0 and cancelled():
                raise WorkCancelled
            value = first.data[position - first.start]
            status = (
                "known"
                if all(
                    segments[i].data[position - segments[i].start] == value
                    for i in contributors[1:]
                )
                else "ambiguous"
            )
            if last_status is not None and status != last_status:
                append(run_start, position, last_status, contributors)
                run_start = position
            last_status = status
        append(run_start, right, last_status, contributors)
    issues = tuple(
        StreamIssue(byte_range=s.byte_range, status=s.status, diagnostic=f"tcp_{s.status}")
        for s in spans
        if s.status != "known"
    )
    return RebuiltStream(
        id=stream_id,
        session_id=session_id,
        direction=direction,
        reconstruction_version=VERSION,
        reconstruction_policy=POLICY,
        extent=extent,
        issues=issues,
        spans=tuple(spans),
    )


def reconstruct(
    capture_id: UUID,
    packets: Iterable[IndexedPacket],
    source: Callable[[IndexedPacket], bytes],
    settings: ReconstructionSettings | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int], None] = lambda _done, _total: None,
) -> Reconstruction:
    settings = settings or ReconstructionSettings()
    connections, excluded = sessionize(packets, settings, cancelled)
    sessions = []
    domains = {(c.packets[0].section_index, c.packets[0].interface_id) for c in connections}
    for index, connection in enumerate(connections):
        if cancelled():
            raise WorkCancelled
        first = connection.packets[0]
        session_id = uuid5(capture_id, f"{VERSION}:session:{first.index}")
        streams = []
        diagnostics = list(dict.fromkeys(connection.issues))
        if len(domains) > 1:
            diagnostics.append("cross_observation_domain_identity_unknown")
        for direction in ("a_to_b", "b_to_a"):
            try:
                streams.append(
                    rebuild_stream(connection, session_id, direction, source, settings, cancelled)
                )
            except ValueError as exc:
                # Scope failure to this direction, retaining other connections and originals.
                diagnostics.append(f"{direction}:{exc}")
        sessions.append(
            RebuiltSession(
                id=session_id,
                capture_id=capture_id,
                section_index=first.section_index,
                interface_id=first.interface_id,
                endpoint_a=Endpoint(address=connection.a[0], port=connection.a[1]),
                endpoint_b=Endpoint(address=connection.b[0], port=connection.b[1]),
                first_packet_id=first.id,
                start_known=connection.start_known,
                roles_known=connection.roles_known,
                diagnostics=tuple(diagnostics),
                packet_ids=tuple(p.id for p in connection.packets),
                closed=connection.closed,
                streams=tuple(streams),
            )
        )
        progress(index + 1, len(connections))
    return Reconstruction(
        capture_id=capture_id,
        settings=settings,
        sessions=tuple(sessions),
        excluded_packet_ids=tuple(excluded),
    )
