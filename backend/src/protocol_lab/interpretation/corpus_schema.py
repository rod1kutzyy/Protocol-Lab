"""Closed relational DSL. Field paths address decoded facts, never executable expressions."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from protocol_lab.domain.models import ByteRange, Record
from protocol_lab.interpretation.checksums import REGISTRY

Path = Annotated[
    str,
    Field(
        pattern=r"^[A-Za-z][A-Za-z0-9_]*(?:\[[0-9]{1,4}\]|\.[A-Za-z][A-Za-z0-9_]*)*$",
        max_length=512,
    ),
]
DecimalInteger = Annotated[str, Field(pattern=r"^-?(0|[1-9][0-9]*)$", max_length=40)]
AlgorithmID = Literal[
    "xor8",
    "sum8",
    "sum16",
    "internet_checksum",
    "CRC-8/SMBUS",
    "CRC-16/ARC",
    "CRC-16/IBM-3740",
    "CRC-16/IBM-SDLC",
    "CRC-32/ISO-HDLC",
]


class ChecksumCheck(Record):
    kind: Literal["checksum"]
    field: Path
    algorithm: AlgorithmID
    byte_order: Literal["big", "little"]
    coverage: Literal["message", "before_field", "ranges"] = "message"
    covered_ranges: tuple[ByteRange, ...] = Field(default=(), max_length=16)
    exclude_field: bool = Field(default=True, strict=True)
    coverage_start: int = Field(default=0, strict=True, ge=0, le=16777216)

    @model_validator(mode="after")
    def ranges(self):
        if (self.coverage == "ranges") != bool(self.covered_ranges):
            raise ValueError("Explicit checksum ranges required only for ranges coverage")
        if self.coverage == "ranges" and self.coverage_start:
            raise ValueError("coverage_start is only for dynamic message/before_field coverage")
        previous = 0
        for interval in self.covered_ranges:
            if interval.start < previous:
                raise ValueError("Checksum ranges must be ordered and nonoverlapping")
            previous = interval.end
        if self.algorithm not in REGISTRY:
            raise ValueError("Unregistered checksum algorithm")
        return self


class CounterCheck(Record):
    kind: Literal["counter"]
    name: Path
    field: Path
    scope: Literal["directed_stream"] = "directed_stream"
    step: Literal["fixed", "message_length", "payload_length"] = "fixed"
    increment: int = Field(default=1, strict=True, ge=1, le=2**53 - 1)
    payload_field: Path | None = None
    wrap: bool = Field(default=True, strict=True)

    @model_validator(mode="after")
    def payload(self):
        if (self.step == "payload_length") != (self.payload_field is not None):
            raise ValueError("payload_length requires an explicit payload field")
        return self


class CopiedValueCheck(Record):
    kind: Literal["copied_value"]
    name: Path
    source_field: Path
    target_field: Path
    source_direction: Literal["a_to_b", "b_to_a"]
    order: Literal["packet_time"] = "packet_time"


class TimestampCheck(Record):
    kind: Literal["timestamp"]
    name: Path
    field: Path
    unit: Literal["s", "ms", "us", "ns"]
    epoch: Literal["unix", "session_relative"]
    clock_offset_ns: DecimalInteger = "0"
    reference_ns: DecimalInteger = "0"
    tolerance_ns: int = Field(default=0, strict=True, ge=0, le=2**53 - 1)
    drift_ppm: int = Field(default=0, strict=True, ge=-1000000, le=1000000)


class EventAssociationCheck(Record):
    kind: Literal["event_association"]
    name: Path
    before_ns: int = Field(default=0, strict=True, ge=0, le=2**53 - 1)
    after_ns: int = Field(default=1000000000, strict=True, ge=0, le=2**53 - 1)


class ParameterMappingCheck(Record):
    kind: Literal["parameter_mapping"]
    name: Path
    field: Path
    parameter_path: tuple[Annotated[str, Field(min_length=1, max_length=200)], ...] = Field(
        min_length=1, max_length=16
    )
    encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be", "decimal", "integer"]
    base64: Literal["none", "standard", "urlsafe"] = "none"
    padding: bool = Field(default=True, strict=True)
    bom: bool = Field(default=False, strict=True)
    width: Literal[1, 2, 4, 8] = 4
    endian: Literal["big", "little"] = "little"
    signed: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def representation(self):
        if self.bom and self.encoding not in {"utf-16le", "utf-16be"}:
            raise ValueError("BOM requires explicit UTF-16 representation")
        return self


CorpusCheck = Annotated[
    CounterCheck
    | CopiedValueCheck
    | TimestampCheck
    | EventAssociationCheck
    | ParameterMappingCheck,
    Field(discriminator="kind"),
]
