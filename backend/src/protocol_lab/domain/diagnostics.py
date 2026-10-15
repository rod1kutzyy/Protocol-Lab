"""Resource exhaustion is not a contradiction of a protocol rule."""

from typing import Literal

from pydantic import Field, model_validator

from protocol_lab.domain.models import Record


class TechnicalLimit(Record):
    name: Literal["max_array_items", "max_message_bytes", "max_decoded_fields"]
    # Computed uint64 lengths can exceed JavaScript's exact integer range.
    observed: str = Field(pattern=r"^(0|[1-9][0-9]*)$", max_length=40)
    maximum: str = Field(pattern=r"^(0|[1-9][0-9]*)$", max_length=40)
    observed_is_lower_bound: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def exceeded(self):
        if int(self.observed) <= int(self.maximum):
            raise ValueError("Technical limit requires observed > maximum")
        return self


def technical_limit(name, observed, maximum, *, lower_bound=False):
    return TechnicalLimit(
        name=name,
        observed=str(observed),
        maximum=str(maximum),
        observed_is_lower_bound=lower_bound,
    )
