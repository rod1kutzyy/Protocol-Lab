"""Bounded direct PCAP/PCAPNG indexing with exact file provenance, using dpkt."""

import hashlib
import socket
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid5

import dpkt
from pydantic import Field, field_serializer

from protocol_lab.domain.models import Offset, Packet, Record

ChecksumPolicy = Literal["warn", "ignore", "reject"]


class CaptureError(ValueError):
    """Source cannot be safely indexed; no completed artifact should be published."""


class WorkCancelled(Exception):
    pass


class IndexedPacket(Packet):
    timestamp_ns: int | None  # Simple Packet Blocks do not contain time.
    section_index: Offset = 0
    interface_id: Offset = 0
    linktype: int
    record_offset: Offset
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    ip_protocol: int | None = None
    ip_header_length: int | None = None
    ip_total_length: int | None = None
    tcp_header_length: int | None = None
    tcp_sequence: int | None = None
    tcp_acknowledgment: int | None = None
    tcp_flags: int | None = None
    declared_payload_length: Offset | None = None
    ipv4_checksum: Literal["valid", "invalid", "unchecked", "unavailable"] = "unavailable"
    tcp_checksum: Literal["valid", "invalid", "unchecked", "unavailable"] = "unavailable"
    eligible_for_reassembly: bool = False

    @field_serializer("timestamp_ns", when_used="json")
    def serialize_time(self, value: int | None) -> str | None:
        # Nanosecond epoch exceeds JavaScript's exact integer range.
        return str(value) if value is not None else None


class IndexSettings(Record):
    checksum_policy: ChecksumPolicy = "warn"
    max_block_bytes: int = Field(default=16 * 1024 * 1024, ge=1024)
    max_packets: int = Field(default=1_000_000, ge=1)


@dataclass(frozen=True)
class Frame:
    data: bytes
    record_offset: int
    file_offset: int
    original_length: int
    timestamp_ns: int | None
    linktype: int
    section: int = 0
    interface: int = 0
    issues: tuple[str, ...] = ()


def capture_format(path: Path) -> Literal["pcap", "pcapng"]:
    with path.open("rb") as source:
        magic = source.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if magic in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    ):
        return "pcap"
    raise CaptureError("Unsupported capture magic at file range [0,4); no usable index")


def sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _exact(source, size: int, offset: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise CaptureError(
            f"Truncated capture at file range [{offset},{offset + size}); no usable index"
        )
    return data


def _pcap(
    path: Path,
    settings: IndexSettings,
    cancelled: Callable[[], bool],
    warning: Callable[[int, int], None],
) -> Iterator[Frame]:
    with path.open("rb") as source:
        raw = _exact(source, 24, 0)
        little = raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        cls = dpkt.pcap.LEFileHdr if little else dpkt.pcap.FileHdr
        header = cls(raw)
        if (header.v_major, header.v_minor) != (2, 4):
            raise CaptureError("Unsupported PCAP version; no usable index")
        packet_cls = dpkt.pcap.LEPktHdr if little else dpkt.pcap.PktHdr
        nano = raw[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        unit = 1 if nano else 1000
        divisor = 1_000_000_000 if nano else 1_000_000
        while True:
            if cancelled():
                raise WorkCancelled
            offset = source.tell()
            raw_header = source.read(16)
            if not raw_header:
                return
            if len(raw_header) != 16:
                raise CaptureError(f"Truncated packet record header at file offset {offset}")
            packet = packet_cls(raw_header)
            if packet.caplen > settings.max_block_bytes:
                raise CaptureError(f"Packet at offset {offset} exceeds max_block_bytes")
            if packet.caplen > packet.len or (header.snaplen and packet.caplen > header.snaplen):
                raise CaptureError(f"Invalid captured length at file offset {offset}")
            issues = () if packet.tv_usec < divisor else ("invalid_timestamp_fraction",)
            yield Frame(
                data=_exact(source, packet.caplen, offset + 16),
                record_offset=offset,
                file_offset=offset + 16,
                original_length=packet.len,
                timestamp_ns=packet.tv_sec * 1_000_000_000 + packet.tv_usec * unit
                if packet.tv_usec < divisor
                else None,
                linktype=header.linktype & 0xFFFF,
                issues=issues,
            )


def _pcapng(
    path: Path,
    settings: IndexSettings,
    cancelled: Callable[[], bool],
    warning: Callable[[int, int], None],
) -> Iterator[Frame]:
    with path.open("rb") as source:
        endian = None
        section = -1
        interfaces: list[
            tuple[int, int, int, int]
        ] = []  # linktype, snaplen, divisor, offset seconds
        while True:
            if cancelled():
                raise WorkCancelled
            offset = source.tell()
            head = source.read(8)
            if not head:
                return
            if len(head) != 8:
                raise CaptureError(f"Truncated PCAPNG block header at offset {offset}")
            if head[:4] == b"\x0a\x0d\x0d\x0a":
                bom = _exact(source, 4, offset + 8)
                if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                    raise CaptureError(f"Invalid PCAPNG byte order at offset {offset}")
                endian = "<" if bom[0] == 0x4D else ">"
                head += bom
                section += 1
                interfaces = []
            if endian is None:
                raise CaptureError("PCAPNG has no initial section")
            kind, size = struct.unpack(endian + "II", head[:8])
            if size < 12 or size % 4 or size > settings.max_block_bytes or size < len(head) + 4:
                raise CaptureError(f"Invalid or over-limit PCAPNG block length at offset {offset}")
            raw = head + _exact(source, size - len(head), offset + len(head))
            if struct.unpack(endian + "I", raw[-4:])[0] != size:
                raise CaptureError(f"Mismatching PCAPNG block lengths at offset {offset}")
            suffix = "LE" if endian == "<" else ""
            if kind == 0x0A0D0D0A:
                shb = getattr(dpkt.pcapng, "SectionHeaderBlock" + suffix)(raw)
                if (shb.v_major, shb.v_minor) != (1, 0):
                    raise CaptureError(f"Unsupported PCAPNG section version at offset {offset}")
            elif kind == 1:
                interface = getattr(dpkt.pcapng, "InterfaceDescriptionBlock" + suffix)(raw)
                divisor, tsoffset = 1_000_000, 0
                for option in interface.opts:
                    if option.code == 9:
                        if len(option.data) != 1:
                            raise CaptureError(f"Invalid if_tsresol at offset {offset}")
                        resol = option.data[0]
                        divisor = (2 if resol & 128 else 10) ** (resol & 127)
                    elif option.code == 14:
                        if len(option.data) != 8:
                            raise CaptureError(f"Invalid if_tsoffset at offset {offset}")
                        tsoffset = struct.unpack(endian + "q", option.data)[0]
                interfaces.append((interface.linktype, interface.snaplen, divisor, tsoffset))
            elif kind in (2, 6):
                if size < 32:
                    raise CaptureError(f"Short PCAPNG packet block at offset {offset}")
                cls = "PacketBlock" if kind == 2 else "EnhancedPacketBlock"
                packet = getattr(dpkt.pcapng, cls + suffix)(raw)
                if packet.iface_id >= len(interfaces):
                    raise CaptureError(f"Unknown interface at PCAPNG offset {offset}")
                linktype, snaplen, divisor, tsoffset = interfaces[packet.iface_id]
                if (
                    packet.caplen > packet.pkt_len
                    or (snaplen and packet.caplen > snaplen)
                    or 28 + ((packet.caplen + 3) & ~3) + 4 > size
                ):
                    raise CaptureError(f"Invalid PCAPNG packet length at offset {offset}")
                ticks = (packet.ts_high << 32) | packet.ts_low
                ns, remainder = divmod(ticks * 1_000_000_000, divisor)
                yield Frame(
                    packet.pkt_data,
                    offset,
                    offset + 28,
                    packet.pkt_len,
                    ns + tsoffset * 1_000_000_000,
                    linktype,
                    section,
                    packet.iface_id,
                    ("timestamp_rounded_to_ns",) if remainder else (),
                )
            elif kind == 3:
                if size < 16 or not interfaces:
                    raise CaptureError(f"Invalid Simple Packet Block at offset {offset}")
                original = struct.unpack(endian + "I", raw[8:12])[0]
                linktype, snaplen, _, _ = interfaces[0]
                captured = min(original, snaplen) if snaplen else original
                if size != 16 + ((captured + 3) & ~3):
                    raise CaptureError(f"Invalid Simple Packet Block length at offset {offset}")
                yield Frame(
                    raw[12 : 12 + captured],
                    offset,
                    offset + 12,
                    original,
                    None,
                    linktype,
                    section,
                    0,
                    ("timestamp_unavailable",),
                )
            else:
                # Preserve original bytes, expose skipped block types instead of claiming support.
                warning(kind, offset)


def decode_frame(
    frame: Frame, capture_id: UUID, index: int, policy: ChecksumPolicy
) -> IndexedPacket:
    data = frame.data
    values = dict(
        id=uuid5(capture_id, str(index)),
        capture_id=capture_id,
        index=index,
        timestamp_ns=frame.timestamp_ns,
        file_offset=frame.file_offset,
        record_offset=frame.record_offset,
        captured_length=len(data),
        original_length=frame.original_length,
        linktype=frame.linktype,
        section_index=frame.section,
        interface_id=frame.interface,
    )
    issues = list(frame.issues)
    if len(data) < frame.original_length:
        issues.append("capture_truncated")
    try:
        if frame.linktype == 1:
            eth_type = struct.unpack("!H", data[12:14])[0]
            ip_start = 14
            for _ in range(2):
                if eth_type not in (0x8100, 0x88A8, 0x9100):
                    break
                eth_type = struct.unpack("!H", data[ip_start + 2 : ip_start + 4])[0]
                ip_start += 4
            if eth_type != 0x0800:
                issues.append("unsupported_network_protocol")
                return IndexedPacket(**values, diagnostics=tuple(issues))
        elif frame.linktype in (12, 101, 228):
            ip_start = 0
        elif frame.linktype == 113:
            if len(data) < 16:
                raise ValueError("truncated cooked header")
            if struct.unpack("!H", data[14:16])[0] != 0x0800:
                issues.append("unsupported_network_protocol")
                return IndexedPacket(**values, diagnostics=tuple(issues))
            ip_start = 16
        else:
            issues.append("unsupported_linktype")
            return IndexedPacket(**values, diagnostics=tuple(issues))
        ip_bytes = data[ip_start:]
        if len(ip_bytes) < 20:
            raise ValueError("truncated IPv4 header")
        ihl = (ip_bytes[0] & 15) * 4
        # Decode only supported headers, never recursively traverse encapsulated payloads.
        ip = dpkt.ip.IP(ip_bytes[:ihl])
        if ip.v != 4 or ihl < 20 or ihl > len(ip_bytes) or ip.len < ihl:
            raise ValueError("invalid IPv4 header")
        values.update(
            source_ip=socket.inet_ntoa(ip.src),
            destination_ip=socket.inet_ntoa(ip.dst),
            ip_protocol=ip.p,
            ip_header_length=ihl,
            ip_total_length=ip.len,
        )
        values["ipv4_checksum"] = (
            "unchecked"
            if policy == "ignore"
            else ("valid" if dpkt.in_cksum(ip_bytes[:ihl]) == 0 else "invalid")
        )
        if values["ipv4_checksum"] == "invalid":
            issues.append("ipv4_checksum_invalid")
        if len(ip_bytes) < ip.len:
            issues.append("ipv4_truncated")
        if ip.mf or ip.offset:
            issues.append("ipv4_fragmented_unsupported")
            return IndexedPacket(**values, diagnostics=tuple(issues))
        if ip.p != 6:
            issues.append("non_tcp")
            return IndexedPacket(**values, diagnostics=tuple(issues))
        tcp_bytes = ip_bytes[ihl : ip.len]
        tcp = dpkt.tcp.TCP(tcp_bytes)
        thl = tcp.off * 4
        if thl < 20 or thl > len(tcp_bytes) or ip.len < ihl + thl:
            raise ValueError("invalid TCP header")
        declared = ip.len - ihl - thl
        values.update(
            source_port=tcp.sport,
            destination_port=tcp.dport,
            tcp_sequence=tcp.seq,
            tcp_acknowledgment=tcp.ack,
            tcp_flags=tcp.flags,
            tcp_header_length=thl,
            payload_offset=ip_start + ihl + thl,
            payload_length=len(tcp_bytes) - thl,
            declared_payload_length=declared,
            eligible_for_reassembly=True,
        )
        if policy == "ignore":
            values["tcp_checksum"] = "unchecked"
        elif len(ip_bytes) >= ip.len:
            pseudo = struct.pack("!4s4sBBH", ip.src, ip.dst, 0, 6, ip.len - ihl)
            values["tcp_checksum"] = (
                "valid" if dpkt.in_cksum(pseudo + tcp_bytes) == 0 else "invalid"
            )
            if values.get("tcp_checksum") == "invalid":
                issues.append("tcp_checksum_invalid")
        else:
            issues.append("tcp_checksum_unavailable")
        if policy == "reject" and (
            values["ipv4_checksum"] == "invalid" or values.get("tcp_checksum") == "invalid"
        ):
            values["eligible_for_reassembly"] = False
            issues.append("checksum_policy_rejected")
    except (dpkt.UnpackError, ValueError, struct.error, IndexError):
        values["eligible_for_reassembly"] = False
        issues.append("malformed_or_truncated_headers")
    return IndexedPacket(**values, diagnostics=tuple(issues))


def index_capture(
    path: Path,
    capture_id: UUID,
    settings: IndexSettings,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int], None] = lambda _done, _total: None,
    container_warning: Callable[[int, int], None] = lambda _kind, _offset: None,
) -> Iterator[IndexedPacket]:
    reader = _pcapng if capture_format(path) == "pcapng" else _pcap
    size = path.stat().st_size
    try:
        for index, frame in enumerate(reader(path, settings, cancelled, container_warning)):
            if index >= settings.max_packets:
                raise CaptureError("Capture exceeds max_packets; no usable index")
            yield decode_frame(frame, capture_id, index, settings.checksum_policy)
            if index % 128 == 0:
                progress(frame.file_offset + len(frame.data), size)
        progress(size, size)
    except dpkt.UnpackError as exc:
        raise CaptureError("Malformed capture container; no usable index") from exc
