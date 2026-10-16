"""Versioned, bounded declarative language. References are local earlier integer fields."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from protocol_lab.domain.models import Record
from protocol_lab.framing.engine import FramingSpec
from protocol_lab.interpretation.corpus_schema import ChecksumCheck, CorpusCheck

Name = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")]
Integer = Annotated[int, Field(strict=True)]
Size = Annotated[int, Field(strict=True, ge=0, le=16777216)]


class Linear(Record):
    field: Name
    multiplier: Annotated[int, Field(strict=True, ge=1, le=65536)] = 1
    add: Annotated[int, Field(strict=True, ge=-16777216, le=16777216)] = 0


Length = Size | Linear


class Remaining(Record):
    remaining_minus: Size


class IntField(Record):
    kind: Literal["int"]
    name: Name
    width: Literal[1, 2, 4, 8]
    signed: bool = Field(strict=True)
    endian: Literal["big", "little"]
    constant: Integer | None = None
    minimum: Integer | None = None
    maximum: Integer | None = None

    @field_validator("width", mode="before")
    @classmethod
    def integer_width(cls, value):
        if type(value) is not int:
            raise ValueError("Integer width must be an integer, not a boolean or float")
        return value

    @model_validator(mode="after")
    def bounds(self):
        low = -(1 << (8 * self.width - 1)) if self.signed else 0
        high = (1 << (8 * self.width - int(self.signed))) - 1
        if any(
            v is not None and not low <= v <= high
            for v in (self.constant, self.minimum, self.maximum)
        ):
            raise ValueError("Integer check does not fit width/signedness")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum exceeds maximum")
        return self


class BytesField(Record):
    kind: Literal["bytes"]
    name: Name
    length: Length | Remaining | Literal["remaining"]
    constant_hex: str | None = Field(
        default=None, max_length=8192, pattern=r"^(?:[a-fA-F0-9]{2})*$"
    )


class DelimitedBytesField(Record):
    kind: Literal["delimited_bytes"]
    name: Name
    terminator_hex: str = Field(min_length=2, max_length=128, pattern=r"^(?:[a-fA-F0-9]{2})+$")
    include_terminator: bool = Field(default=False, strict=True)
    max_length: Annotated[int, Field(strict=True, ge=1, le=16777216)]
    missing_terminator: Literal["failed"] = "failed"


class ArrayField(Record):
    kind: Literal["array"]
    name: Name
    count: Length
    fields: tuple["FieldSpec", ...] = Field(min_length=1, max_length=128)


class SwitchField(Record):
    kind: Literal["switch"]
    name: Name
    selector: Name
    cases: dict[str, tuple["FieldSpec", ...]] = Field(min_length=1, max_length=32)


FieldSpec = Annotated[
    IntField | BytesField | DelimitedBytesField | ArrayField | SwitchField,
    Field(discriminator="kind"),
]
ArrayField.model_rebuild()
SwitchField.model_rebuild()


class LengthCheck(Record):
    kind: Literal["length"]
    field: Name  # bytes => byte count; array => item count; switch => consumed bytes
    expected: Length


class ProtocolModel(Record):
    schema_version: Literal["interpretation-1", "interpretation-2"]
    name: str = Field(min_length=1, max_length=200)
    direction: Literal["both", "a_to_b", "b_to_a"] = "both"
    framing: FramingSpec
    fields: tuple[FieldSpec, ...] = Field(min_length=1, max_length=128)
    checks: tuple[Annotated[LengthCheck | ChecksumCheck, Field(discriminator="kind")], ...] = Field(
        default=(), max_length=128
    )
    corpus_checks: tuple[CorpusCheck, ...] = Field(default=(), max_length=128)
    max_corpus_units: int = Field(default=100000, strict=True, ge=1, le=1000000)
    max_corpus_bytes: int = Field(default=16777216, strict=True, ge=1, le=268435456)
    max_checksum_bytes: int = Field(default=16777216, strict=True, ge=1, le=16777216)
    max_array_items: Annotated[int, Field(strict=True, ge=1, le=4096)] = 1024
    max_decoded_fields: Annotated[int, Field(strict=True, ge=1, le=16384)] = 4096

    @model_validator(mode="after")
    def references(self):
        total = 0
        v2_fields = False

        def check_reference(expr, integers):
            if isinstance(expr, Linear) and expr.field not in integers:
                raise ValueError(f"Reference {expr.field!r} must be an earlier local integer field")

        def walk(fields, depth):
            nonlocal total, v2_fields
            if depth > 8:
                raise ValueError("Model nesting exceeds 8 levels")
            names, integers = set(), set()
            for field in fields:
                total += 1
                if total > 512:
                    raise ValueError("Model exceeds 512 field definitions")
                if field.name in names:
                    raise ValueError(f"Duplicate field name {field.name!r}")
                if isinstance(field, BytesField):
                    check_reference(field.length, integers)
                    if isinstance(field.length, Remaining):
                        v2_fields = True
                elif isinstance(field, DelimitedBytesField):
                    v2_fields = True
                elif isinstance(field, ArrayField):
                    check_reference(field.count, integers)
                    if isinstance(field.count, int) and field.count > self.max_array_items:
                        raise ValueError("Static array count exceeds max_array_items")
                    walk(field.fields, depth + 1)
                elif isinstance(field, SwitchField):
                    if field.selector not in integers:
                        raise ValueError("Switch selector must be an earlier local integer field")
                    for key, branch in field.cases.items():
                        if len(key) > 21 or not key.lstrip("-").isdigit() or str(int(key)) != key:
                            raise ValueError("Switch case keys must be canonical decimal integers")
                        if not branch or len(branch) > 128:
                            raise ValueError("Switch branches require 1..128 fields")
                        walk(branch, depth + 1)
                names.add(field.name)
                if isinstance(field, IntField):
                    integers.add(field.name)
            return names, integers

        names, integers = walk(self.fields, 1)
        if self.schema_version == "interpretation-1" and (
            v2_fields
            or self.corpus_checks
            or any(isinstance(c, ChecksumCheck) for c in self.checks)
        ):
            raise ValueError("delimited_bytes/checksum/corpus_checks require interpretation-2")
        for check in self.checks:
            if isinstance(check, ChecksumCheck):
                root = check.field.split(".")[0].split("[")[0]
                if root not in names:
                    raise ValueError(f"Checksum field {check.field!r} does not exist")
                continue
            if check.field not in names:
                raise ValueError(f"Length check field {check.field!r} does not exist")
            if isinstance(next(f for f in self.fields if f.name == check.field), IntField):
                raise ValueError("Length checks target bytes, arrays or switches")
            check_reference(check.expected, integers)
        if len({check.name for check in self.corpus_checks}) != len(self.corpus_checks):
            raise ValueError("Duplicate corpus check name")
        for check in self.corpus_checks:
            for attribute in ("field", "source_field", "target_field", "payload_field"):
                path = getattr(check, attribute, None)
                if path is not None and path.split(".")[0].split("[")[0] not in names:
                    raise ValueError(f"Corpus check field {path!r} does not exist")
        return self


def canonical(model: ProtocolModel):
    data = model.model_dump(mode="json")
    # Additive DSL defaults must not change the hashes of existing portable models.
    for key in ("direction", "corpus_checks", "max_corpus_units", "max_corpus_bytes", "max_checksum_bytes"):
        default = ProtocolModel.model_fields[key].default
        if getattr(model, key) == default:
            data.pop(key)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def content_hash(model: ProtocolModel):
    return hashlib.sha256(canonical(model).encode()).hexdigest()


def json_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:protocol-lab:interpretation-2",
        **ProtocolModel.model_json_schema(),
    }
