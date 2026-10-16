"""Versioned finite checksum registry, independent of packet checksum policy."""

from dataclasses import dataclass
from functools import lru_cache

from protocol_lab.capture.index import WorkCancelled


@dataclass(frozen=True)
class Algorithm:
    width: int
    check: int  # ASCII b"123456789"
    poly: int = 0
    init: int = 0
    refin: bool = False
    refout: bool = False
    xorout: int = 0


REGISTRY = {
    "xor8": Algorithm(8, 0x31),
    "sum8": Algorithm(8, 0xDD),
    "sum16": Algorithm(16, 0x1DD),
    "internet_checksum": Algorithm(16, 0xF62A),
    "CRC-8/SMBUS": Algorithm(8, 0xF4, 0x07),
    "CRC-16/ARC": Algorithm(16, 0xBB3D, 0x8005, refin=True, refout=True),
    "CRC-16/IBM-3740": Algorithm(16, 0x29B1, 0x1021, 0xFFFF),
    "CRC-16/IBM-SDLC": Algorithm(16, 0x906E, 0x1021, 0xFFFF, True, True, 0xFFFF),
    "CRC-32/ISO-HDLC": Algorithm(32, 0xCBF43926, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
}
VERSION = "checksum-registry-1"


def reflect(value, width):
    return int(f"{value:0{width}b}"[::-1], 2)


@lru_cache(maxsize=9)
def table(name):
    spec = REGISTRY[name]
    mask = (1 << spec.width) - 1
    polynomial = reflect(spec.poly, spec.width) if spec.refin else spec.poly
    values = []
    for byte in range(256):
        value = byte if spec.refin else byte << (spec.width - 8)
        for _ in range(8):
            if spec.refin:
                value = (value >> 1) ^ (polynomial if value & 1 else 0)
            else:
                value = (
                    (value << 1) ^ (polynomial if value & (1 << (spec.width - 1)) else 0)
                ) & mask
        values.append(value)
    return tuple(values)


def calculate(name, data, cancelled=lambda: False):
    """Compute over the exact concatenation of covered bytes, including odd Internet lengths."""
    spec = REGISTRY[name]
    if cancelled():
        raise WorkCancelled
    mask = (1 << spec.width) - 1
    if name == "xor8":
        result = 0
        for index, byte in enumerate(data):
            if index % 65536 == 0 and cancelled():
                raise WorkCancelled
            result ^= byte
        return result
    if name in {"sum8", "sum16"}:
        return sum(data) & mask
    if name == "internet_checksum":
        value = sum(
            int.from_bytes(data[i : i + 2], "big") << (8 if i + 1 == len(data) else 0)
            for i in range(0, len(data), 2)
        )
        while value >> 16:
            value = (value & 0xFFFF) + (value >> 16)
        return (~value) & 0xFFFF
    values = table(name)
    result = spec.init
    for index, byte in enumerate(data):
        if index % 65536 == 0 and cancelled():
            raise WorkCancelled
        result = (
            ((result >> 8) ^ values[(result ^ byte) & 255])
            if spec.refin
            else (((result << 8) & mask) ^ values[((result >> (spec.width - 8)) ^ byte) & 255])
        )
    if spec.refin != spec.refout:
        result = reflect(result, spec.width)
    return (result ^ spec.xorout) & mask


def covered_bytes(data, start, end, coverage, ranges=(), exclude_field=True, coverage_start=0):
    """Ranges are ordered, message-relative [start,end); never pad out-of-bounds data."""
    selected = (
        [(coverage_start, len(data))]
        if coverage == "message"
        else (
            [(coverage_start, start)]
            if coverage == "before_field"
            else [(r.start, r.end) for r in ranges]
        )
    )
    result = bytearray()
    for left, right in selected:
        if not 0 <= left <= right <= len(data):
            raise ValueError("checksum coverage outside message")
        if exclude_field and left < end and start < right:
            result.extend(data[left : min(right, start)])
            result.extend(data[max(left, end) : right])
        else:
            result.extend(data[left:right])
    return bytes(result)
