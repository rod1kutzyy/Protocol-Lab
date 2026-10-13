"""Versioned, bounded declarative language. References are local earlier integer fields."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from protocol_lab.domain.models import Record
from protocol_lab.framing.engine import FramingSpec

Name = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")]
Integer = Annotated[int, Field(strict=True)]
Size = Annotated[int, Field(strict=True, ge=0, le=16777216)]


class Linear(Record):
    field: Name
    multiplier: Annotated[int, Field(strict=True, ge=1, le=65536)] = 1
    add: Annotated[int, Field(strict=True, ge=-16777216, le=16777216)] = 0


Length = Size | Linear


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
    length: Length | Literal["remaining"]
    constant_hex: str | None = Field(
        default=None, max_length=8192, pattern=r"^(?:[a-fA-F0-9]{2})*$"
    )


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


FieldSpec = Annotated[IntField | BytesField | ArrayField | SwitchField, Field(discriminator="kind")]
ArrayField.model_rebuild()
SwitchField.model_rebuild()


class LengthCheck(Record):
    kind: Literal["length"]
    field: Name  # bytes => byte count; array => item count; switch => consumed bytes
    expected: Length


class ProtocolModel(Record):
    schema_version: Literal["interpretation-1"]
    name: str = Field(min_length=1, max_length=200)
    framing: FramingSpec
    fields: tuple[FieldSpec, ...] = Field(min_length=1, max_length=128)
    checks: tuple[LengthCheck, ...] = Field(default=(), max_length=128)
    max_array_items: Annotated[int, Field(strict=True, ge=1, le=4096)] = 1024
    max_decoded_fields: Annotated[int, Field(strict=True, ge=1, le=16384)] = 4096

    @model_validator(mode="after")
    def references(self):
        total = 0

        def check_reference(expr, integers):
            if isinstance(expr, Linear) and expr.field not in integers:
                raise ValueError(f"Reference {expr.field!r} must be an earlier local integer field")

        def walk(fields, depth):
            nonlocal total
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
        for check in self.checks:
            if check.field not in names:
                raise ValueError(f"Length check field {check.field!r} does not exist")
            if isinstance(next(f for f in self.fields if f.name == check.field), IntField):
                raise ValueError("Length checks target bytes, arrays or switches")
            check_reference(check.expected, integers)
        return self


def canonical(model: ProtocolModel):
    return json.dumps(model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def content_hash(model: ProtocolModel):
    return hashlib.sha256(canonical(model).encode()).hexdigest()


def json_schema():
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:protocol-lab:interpretation-1",
        **ProtocolModel.model_json_schema(),
    }
