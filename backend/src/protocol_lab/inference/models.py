"""Closed, bounded inference contracts; detector availability is reported separately."""

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter, field_validator, model_validator

from protocol_lab.domain.models import ByteRange, Record, Sha256, SourceRange, StreamRange
from protocol_lab.framing.engine import FramingSpec
from protocol_lab.interpretation.document import load_model
from protocol_lab.interpretation.schema import content_hash as model_hash
from protocol_lab.validation.models import CaptureSnapshot, Status, StoredCorpus

CONTRACT_VERSION = "inference-contracts-1"
Count = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
Positive = Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
Text = Annotated[str, Field(min_length=1, max_length=10000)]
DecimalInteger = Annotated[str, Field(pattern=r"^-?(0|[1-9][0-9]*)$", max_length=40)]
Hex = Annotated[str, Field(pattern=r"^(?:[0-9a-fA-F]{2})+$", max_length=128)]
IDs = Annotated[tuple[UUID, ...], Field(max_length=10000)]
Family = Literal[
    "framing",
    "structure",
    "groups",
    "counters",
    "tokens",
    "checksums",
    "timestamps",
    "entropy",
    "events",
    "data_mapping",
]
FAMILIES = TypeAdapter(Family).json_schema()["enum"]
Checksum = Literal[
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


def unique_ids(value):
    if len(set(value)) != len(value):
        raise ValueError("Duplicate IDs are not allowed")
    return tuple(sorted(value, key=str))


class SearchBudget(Record):
    """Finite operation counts, not assumptions about the investigated protocol."""

    max_sample_messages: int = Field(default=5000, strict=True, ge=1, le=100000)
    max_sample_units: int = Field(default=100000, strict=True, ge=1, le=1000000)
    max_scanned_bytes: int = Field(default=100 * 1024 * 1024, strict=True, ge=1, le=2**40)
    max_header_bytes: int = Field(default=64, strict=True, ge=1, le=65536)
    max_candidates_per_family: int = Field(default=200, strict=True, ge=1, le=10000)
    max_candidates: int = Field(default=2000, strict=True, ge=1, le=100000)
    max_framing_alternatives: int = Field(default=10, strict=True, ge=1, le=100)
    max_refinement_iterations: int = Field(default=2, strict=True, ge=0, le=10)
    max_evidence_bytes: int = Field(default=256 * 1024 * 1024, strict=True, ge=1, le=2**32)
    max_decoded_field_bytes: int = Field(default=1024 * 1024, strict=True, ge=1, le=16777216)
    max_alignment_cells: int = Field(default=1000000, strict=True, ge=1, le=100000000)
    max_candidate_evaluations: int = Field(default=100000, strict=True, ge=1, le=10000000)
    max_checksum_operations: int = Field(default=1000000, strict=True, ge=1, le=100000000)
    max_event_windows: int = Field(default=100000, strict=True, ge=1, le=1000000)
    max_rule_trials: int = Field(default=20000, strict=True, ge=1, le=1000000)
    max_probe_bytes: int = Field(default=65536, strict=True, ge=64, le=1048576)
    max_message_bytes: int = Field(default=1048576, strict=True, ge=1, le=16777216)
    max_marker_positions: int = Field(default=4096, strict=True, ge=1, le=1000000)
    max_probe_streams: int = Field(default=8, strict=True, ge=1, le=128)
    max_screen_messages: int = Field(default=64, strict=True, ge=3, le=4096)
    max_marker_occurrences: int = Field(default=32, strict=True, ge=3, le=4096)
    max_shortlist_per_kind: int = Field(default=48, strict=True, ge=1, le=1000)


class SearchSpace(Record):
    fixed_size_min: int = Field(default=1, strict=True, ge=1, le=16777216)
    fixed_size_max: int = Field(default=4096, strict=True, ge=1, le=16777216)
    multiplier_min: int = Field(default=1, strict=True, ge=1, le=65536)
    multiplier_max: int = Field(default=4, strict=True, ge=1, le=65536)
    adjustment_min: int = Field(default=-64, strict=True, ge=-16777216, le=16777216)
    adjustment_max: int = Field(default=64, strict=True, ge=-16777216, le=16777216)
    marker_max_bytes: int = Field(default=16, strict=True, ge=1, le=64)
    min_repeated_messages: int = Field(default=3, strict=True, ge=2, le=1000)
    min_unique_messages: int = Field(default=2, strict=True, ge=1, le=1000)
    max_marker_patterns: int = Field(default=16, strict=True, ge=1, le=128)
    widths: tuple[Literal[1, 2, 4, 8], ...] = Field(
        default=(1, 2, 4, 8), min_length=1, max_length=4
    )
    endians: tuple[Literal["big", "little"], ...] = Field(
        default=("big", "little"), min_length=1, max_length=2
    )

    @field_validator("widths", mode="before")
    @classmethod
    def strict_widths(cls, value):
        if any(type(width) is not int for width in value):
            raise ValueError("Widths must be integers")
        return value

    @model_validator(mode="after")
    def bounds(self):
        for name in ("fixed_size", "multiplier", "adjustment"):
            if getattr(self, name + "_min") > getattr(self, name + "_max"):
                raise ValueError(f"{name}_min exceeds {name}_max")
        if not self.widths or not self.endians:
            raise ValueError("At least one width and endian must be searched")
        if any(type(width) is not int for width in self.widths):
            raise ValueError("Widths must be integers")
        if len(set(self.widths)) != len(self.widths) or len(set(self.endians)) != len(self.endians):
            raise ValueError("Duplicate search alternatives")
        return self


class DataSplit(Record):
    unit: Literal["capture", "session"] = "capture"
    discovery_ids: IDs = Field(min_length=1)
    holdout_ids: IDs = ()
    holdout_unavailable_reason: Text | None = None

    @field_validator("discovery_ids", "holdout_ids")
    @classmethod
    def canonical_ids(cls, value):
        return unique_ids(value)

    @model_validator(mode="after")
    def independent(self):
        if set(self.discovery_ids) & set(self.holdout_ids):
            raise ValueError("Discovery and holdout must be disjoint")
        if bool(self.holdout_ids) == bool(self.holdout_unavailable_reason):
            raise ValueError("Supply holdout IDs or an explicit reason why holdout is unavailable")
        return self


class SamplingSpec(Record):
    seed: Count = 0
    strategy: Literal["stratified_hash_round_robin_v1"] = "stratified_hash_round_robin_v1"
    deduplication: Literal["payload_sha256"] = "payload_sha256"


class DetectorRequest(Record):
    family: Family
    contract_version: Literal["inference-detector-1"] = "inference-detector-1"


class RecordingGroup(Record):
    """Explicit knowledge that captures observe the same traffic; never inferred from labels."""

    capture_ids: IDs = Field(min_length=2)
    rationale: Text

    @field_validator("capture_ids")
    @classmethod
    def canonical_ids(cls, value):
        return unique_ids(value)


class LogInput(Record):
    log_id: UUID
    sha256: Sha256
    clock_revision: Count
    clock_offset_ns: DecimalInteger
    timestamp_field: Annotated[str, Field(min_length=1, max_length=200)]
    label_field: Annotated[str, Field(min_length=1, max_length=200)]
    parameters_field: Annotated[str, Field(min_length=1, max_length=200)] | None = None
    timestamp_format: Literal["iso8601", "unix_s", "unix_ms", "unix_ns"]
    format: Literal["csv", "json"]
    delimiter: Literal[",", ";", "\t"] = ","


class ParameterInput(Record):
    log_id: UUID | None = None
    event_ids: IDs = ()
    parameter_path: tuple[Annotated[str, Field(min_length=1, max_length=200)], ...] = Field(
        default=(), max_length=16
    )
    text: Annotated[str, Field(min_length=1, max_length=10000)] | None = None

    @model_validator(mode="after")
    def origin(self):
        if self.log_id is None:
            if self.text is None or self.event_ids or self.parameter_path:
                raise ValueError("Explicit text requires no log references")
        elif self.text is not None or not self.event_ids or not self.parameter_path:
            raise ValueError("Log parameter requires events and a path, without literal text")
        unique_ids(self.event_ids)
        return self


class InferenceSpec(Record):
    schema_version: Literal["inference-spec-1"] = "inference-spec-1"
    corpus_version_id: UUID
    mode: Literal["discover", "evaluate"] = "discover"
    candidate_ids: IDs = ()
    detectors: tuple[DetectorRequest, ...] = Field(min_length=1, max_length=10)
    split: DataSplit
    sampling: SamplingSpec = Field(default_factory=SamplingSpec)
    budget: SearchBudget = Field(default_factory=SearchBudget)
    search: SearchSpace = Field(default_factory=SearchSpace)
    framing_version_ids: IDs = ()
    interpretation_version_id: UUID | None = None
    assumptions: tuple[Text, ...] = Field(default=(), max_length=128)
    known_markers: tuple[Hex, ...] = Field(default=(), max_length=128)
    excluded_ranges: tuple[StreamRange, ...] = Field(default=(), max_length=10000)
    recording_groups: tuple[RecordingGroup, ...] = Field(default=(), max_length=1000)
    logs: tuple[LogInput, ...] = Field(default=(), max_length=128)
    parameters: tuple[ParameterInput, ...] = Field(default=(), max_length=128)
    event_before_ns: Count = 0
    event_after_ns: Count = 1000000000
    timestamp_units: tuple[Literal["s", "ms", "us", "ns"], ...] = Field(
        default=("s", "ms", "us", "ns"), min_length=1, max_length=4
    )
    timestamp_epochs: tuple[Literal["unix", "session_relative"], ...] = Field(
        default=("unix", "session_relative"), min_length=1, max_length=2
    )
    checksum_algorithms: tuple[Checksum, ...] = (
        "xor8",
        "sum8",
        "sum16",
        "internet_checksum",
        "CRC-8/SMBUS",
        "CRC-16/ARC",
        "CRC-16/IBM-3740",
        "CRC-16/IBM-SDLC",
        "CRC-32/ISO-HDLC",
    )

    @model_validator(mode="after")
    def references(self):
        families = [d.family for d in self.detectors]
        if len(set(families)) != len(families):
            raise ValueError("Duplicate detector family")
        if (self.mode == "evaluate") != bool(self.candidate_ids):
            raise ValueError("Evaluate requires fixed candidates; discover cannot take candidates")
        unique_ids(self.candidate_ids)
        unique_ids(self.framing_version_ids)
        log_ids = [log.log_id for log in self.logs]
        unique_ids(log_ids)
        if any(p.log_id is not None and p.log_id not in log_ids for p in self.parameters):
            raise ValueError("Parameter refers to a log outside the snapshot inputs")
        if len(set(self.checksum_algorithms)) != len(self.checksum_algorithms):
            raise ValueError("Duplicate checksum algorithm")
        if len(set(self.timestamp_units)) != len(self.timestamp_units) or not self.timestamp_units:
            raise ValueError("Timestamp units must be nonempty and unique")
        if (
            len(set(self.timestamp_epochs)) != len(self.timestamp_epochs)
            or not self.timestamp_epochs
        ):
            raise ValueError("Timestamp epochs must be nonempty and unique")
        return self


class IntegerLocation(Record):
    offset: Count
    width: Literal[1, 2, 4, 8]
    endian: Literal["big", "little"]
    signed: bool = Field(default=False, strict=True)

    @field_validator("width", mode="before")
    @classmethod
    def strict_width(cls, value):
        if type(value) is not int:
            raise ValueError("Width must be an integer")
        return value


class FramingCandidateRule(Record):
    kind: Literal["fixed_framing", "length_framing", "marker_framing"]
    framing: FramingSpec

    @model_validator(mode="after")
    def matching_kind(self):
        expected = {
            "fixed_framing": "fixed",
            "length_framing": "length",
            "marker_framing": "markers",
        }
        if self.framing.rule.kind != expected[self.kind]:
            raise ValueError("Candidate kind and framing rule disagree")
        return self


class RegionRule(Record):
    kind: Literal[
        "constant_region",
        "start_marker",
        "end_marker",
        "fixed_width_region",
        "session_stable_region",
        "session_token_candidate",
        "field_boundary_candidate",
    ]
    relative_to: Literal["message_start", "message_end"] = "message_start"
    offset: Count
    length: Positive
    value_hex: Hex | None = None
    relation_scope: Literal["message_group", "direction", "session"] = "message_group"
    framing: FramingSpec | None = None

    @model_validator(mode="after")
    def constant(self):
        if (
            self.kind in {"constant_region", "start_marker", "end_marker"}
            and self.value_hex is None
        ):
            raise ValueError("Constant/marker requires exact bytes")
        if self.value_hex is not None and len(self.value_hex) // 2 != self.length:
            raise ValueError("Value length differs from region width")
        return self


class LengthRelationRule(Record):
    kind: Literal["length_relation"]
    field: IntegerLocation
    target: Literal["message", "payload", "array"]
    target_offset: Count = 0
    multiplier: int = Field(default=1, strict=True, ge=1, le=65536)
    adjustment: int = Field(default=0, strict=True, ge=-16777216, le=16777216)


class DelimiterRule(Record):
    kind: Literal["field_delimiter"]
    delimiter_hex: Hex
    include_terminator: bool = Field(default=False, strict=True)
    escaping: Literal["none"] = "none"


class GroupRule(Record):
    kind: Literal["message_group", "opcode_candidate"]
    key_fields: tuple[IntegerLocation, ...] = Field(min_length=1, max_length=16)
    masked_ranges: tuple[ByteRange, ...] = Field(default=(), max_length=128)


class CounterRule(Record):
    kind: Literal["counter", "identifier_relation"]
    field: IntegerLocation
    step: Literal["fixed", "message_length", "payload_length"] = "fixed"
    increment: Positive = 1
    scope: Literal["direction", "message_group", "session"] = "direction"
    wrap: bool = Field(default=True, strict=True)
    framing: FramingSpec | None = None


class CopyRelationRule(Record):
    kind: Literal["copied_value"]
    source_offset: Count
    target_offset: Count
    length: Positive
    source_direction: Literal["a_to_b", "b_to_a"]
    framing: FramingSpec


class ChecksumRule(Record):
    kind: Literal["checksum_relation"]
    field: IntegerLocation
    algorithm: Checksum
    covered_ranges: tuple[ByteRange, ...] = Field(default=(), max_length=16)
    exclude_field: bool = Field(default=True, strict=True)
    field_relative_to: Literal["message_start", "message_end"] = "message_start"
    coverage: Literal["message", "before_field", "ranges"] = "ranges"
    coverage_start: Count = 0
    framing: FramingSpec | None = None

    @model_validator(mode="after")
    def parameters(self):
        expected = (
            4
            if self.algorithm == "CRC-32/ISO-HDLC"
            else 2
            if self.algorithm
            in {"sum16", "internet_checksum", "CRC-16/ARC", "CRC-16/IBM-3740", "CRC-16/IBM-SDLC"}
            else 1
        )
        if self.field.width != expected or self.field.signed:
            raise ValueError("Checksum field must match the registered algorithm width")
        if (self.coverage == "ranges") != bool(self.covered_ranges):
            raise ValueError("Explicit checksum ranges required only for ranges coverage")
        if self.coverage == "ranges" and self.coverage_start:
            raise ValueError("coverage_start is only supported for dynamic coverage")
        previous = 0
        for interval in self.covered_ranges:
            if interval.start < previous:
                raise ValueError("Checksum coverage must be ordered and nonoverlapping")
            previous = interval.end
        return self


class TimestampRule(Record):
    kind: Literal["timestamp_candidate", "relative_clock_candidate"]
    field: IntegerLocation
    unit: Literal["s", "ms", "us", "ns"]
    epoch: Literal["unix", "session_relative", "unknown"]
    clock_offset_ns: DecimalInteger = "0"
    tolerance_ns: Count
    drift_ppm: int = Field(default=0, strict=True, ge=-1000000, le=1000000)
    framing: FramingSpec | None = None

    @model_validator(mode="after")
    def width(self):
        if self.field.width not in {4, 8}:
            raise ValueError("Timestamp candidates require a 4- or 8-byte field")
        return self


class ProfileRule(Record):
    kind: Literal["byte_profile", "entropy_region"]
    measurement: Literal["within_block", "sliding_window", "across_messages"]
    window_bytes: int = Field(default=64, strict=True, ge=1, le=65536)


class EventRule(Record):
    kind: Literal["event_association"]
    before_ns: Count
    after_ns: Count
    clock_offset_ns: DecimalInteger = "0"


class MappingRule(Record):
    kind: Literal["parameter_mapping"]
    parameter_path: tuple[Annotated[str, Field(min_length=1, max_length=200)], ...] = Field(
        min_length=1, max_length=16
    )
    encoding: Literal["ascii", "utf-8", "utf-16le", "utf-16be", "decimal", "integer"]
    base64: Literal["none", "standard", "urlsafe"] = "none"
    padding: bool = Field(default=True, strict=True)
    bom: bool = Field(default=False, strict=True)
    integer: IntegerLocation | None = None

    @model_validator(mode="after")
    def representation(self):
        if (self.encoding == "integer") != (self.integer is not None):
            raise ValueError("Integer encoding requires an explicit integer representation")
        if self.bom and self.encoding not in {"utf-16le", "utf-16be"}:
            raise ValueError("BOM is only supported for explicit UTF-16 variants")
        return self


CandidateRule = Annotated[
    FramingCandidateRule
    | RegionRule
    | LengthRelationRule
    | DelimiterRule
    | GroupRule
    | CounterRule
    | CopyRelationRule
    | ChecksumRule
    | TimestampRule
    | ProfileRule
    | EventRule
    | MappingRule,
    Field(discriminator="kind"),
]


class InferenceMetrics(Record):
    unit: Literal["message", "transition", "event", "session"]
    eligible: Count
    matched: Count
    contradicted: Count
    unknown: Count
    ambiguous: Count
    not_applicable: Count
    captures: Count
    sessions: Count
    unique_messages: Count
    distinct_values: Count = 0
    distinct_lengths: Count = 0

    @model_validator(mode="after")
    def accounting(self):
        if self.eligible != self.matched + self.contradicted + self.unknown + self.ambiguous:
            raise ValueError("Eligible units must account for all four applicable outcomes")
        return self


class CandidateScope(Record):
    corpus_version_id: UUID
    capture_ids: IDs = Field(min_length=1)
    session_ids: IDs = ()
    direction: Literal["both", "a_to_b", "b_to_a"] = "both"
    group_id: UUID | None = None

    @field_validator("capture_ids", "session_ids")
    @classmethod
    def canonical_ids(cls, value):
        return unique_ids(value)


class RankingComponents(Record):
    version: Literal["lexicographic-1"] = "lexicographic-1"
    supporting_sessions: Count
    matched: Count
    checked: Count
    explained_bytes: Count
    contradictions: Count
    free_parameters: Count

    @model_validator(mode="after")
    def counts(self):
        if self.matched + self.contradictions != self.checked:
            raise ValueError("Ranking denominator counts only matched/contradicted units")
        return self


class InferenceCandidate(Record):
    schema_version: Literal["inference-candidate-1"] = "inference-candidate-1"
    id: UUID
    run_id: UUID
    family: Family
    detector_version: Text
    rule_schema_version: Literal["inference-rule-1"] = "inference-rule-1"
    rule: CandidateRule
    rule_sha256: Sha256
    scope: CandidateScope
    dependency_ids: IDs = ()
    metrics: InferenceMetrics
    ranking: RankingComponents
    rationale: Text
    assumptions: tuple[Text, ...] = Field(default=(), max_length=128)
    limitations: tuple[Text, ...] = Field(default=(), max_length=128)
    alternatives: IDs = ()
    compiler_support: Literal["interpretation-1", "interpretation-2", "not_compilable"]
    compiler_reason: Text | None = None

    @model_validator(mode="after")
    def identity(self):
        family = {
            FramingCandidateRule: {"framing"},
            LengthRelationRule: {"framing", "structure"},
            DelimiterRule: {"structure"},
            GroupRule: {"groups"},
            CounterRule: {"counters"},
            CopyRelationRule: {"tokens"},
            ChecksumRule: {"checksums"},
            TimestampRule: {"timestamps"},
            ProfileRule: {"entropy"},
            EventRule: {"events"},
            MappingRule: {"data_mapping"},
        }.get(type(self.rule))
        if isinstance(self.rule, RegionRule):
            family = (
                {"tokens"}
                if self.rule.kind in {"session_stable_region", "session_token_candidate"}
                else {"structure", "entropy"}
                if self.rule.kind == "field_boundary_candidate"
                else {"structure", "framing"}
            )
        if self.family not in family:
            raise ValueError("Candidate rule does not belong to the declared detector family")
        if self.rule_sha256 != content_hash(self.rule):
            raise ValueError("Rule hash mismatch")
        if (
            self.ranking.matched != self.metrics.matched
            or self.ranking.contradictions != self.metrics.contradicted
            or self.ranking.supporting_sessions > self.metrics.sessions
        ):
            raise ValueError("Ranking components must agree with candidate metrics")
        if self.id in self.dependency_ids or self.id in self.alternatives:
            raise ValueError("Candidate cannot depend on or be an alternative to itself")
        if self.compiler_support == "not_compilable" and not self.compiler_reason:
            raise ValueError("Unsupported compilation requires an explanation")
        if self.compiler_support == "interpretation-1" and self.rule.kind not in {
            "fixed_framing",
            "length_framing",
            "marker_framing",
            "constant_region",
            "fixed_width_region",
            "length_relation",
            "opcode_candidate",
        }:
            raise ValueError("Rule cannot be executed by interpretation-1")
        if self.compiler_support == "interpretation-2" and (
            not isinstance(self.rule, (CounterRule, TimestampRule, ChecksumRule))
            or self.rule.framing is None
        ):
            raise ValueError("Rule cannot be executed by interpretation-2")
        unique_ids(self.dependency_ids)
        unique_ids(self.alternatives)
        return self


class CandidateEvidence(Record):
    candidate_id: UUID
    status: Status
    anchor: StreamRange | None = None
    sources: tuple[SourceRange, ...] = Field(default=(), max_length=1000)
    event_id: UUID | None = None
    diagnostic: Text
    preview_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-fA-F]{2})*$", max_length=128)] = ""

    @model_validator(mode="after")
    def provenance(self):
        if self.status in {"passed", "failed"} and self.anchor is None and self.event_id is None:
            raise ValueError("A checked fact requires source or event provenance")
        for source in self.sources:
            a = source.stream
            if self.anchor is None or (
                a.stream_id != self.anchor.stream_id
                or a.reconstruction_version != self.anchor.reconstruction_version
                or a.byte_range.start < self.anchor.byte_range.start
                or a.byte_range.end > self.anchor.byte_range.end
            ):
                raise ValueError("Source range is outside the evidence anchor")
        return self


class VersionRef(Record):
    id: UUID
    sha256: Sha256


class InterpretationInput(VersionRef):
    document_json: str = Field(max_length=262144)

    @model_validator(mode="after")
    def document_hash(self):
        if model_hash(load_model(self.document_json)) != self.sha256:
            raise ValueError("Interpretation document hash mismatch")
        return self


class FramingInput(VersionRef):
    spec: FramingSpec
    stream_id: UUID | None = None

    @model_validator(mode="after")
    def spec_hash(self):
        if content_hash(self.spec) != self.sha256:
            raise ValueError("Framing specification hash mismatch")
        return self


class CandidateInput(VersionRef):
    rule_schema_version: Literal["inference-rule-1"] = "inference-rule-1"
    rule: CandidateRule

    @model_validator(mode="after")
    def rule_hash(self):
        if content_hash(self.rule) != self.sha256:
            raise ValueError("Frozen candidate rule hash mismatch")
        return self


class FrozenEventInput(Record):
    """Action-log row with the clock correction frozen at discovery time."""

    id: UUID
    log_id: UUID
    timestamp_ns: DecimalInteger
    label: Annotated[str, Field(min_length=1, max_length=500)]
    parameters_json: Annotated[str, Field(max_length=10000)]


class EngineVersions(Record):
    contracts: Literal["inference-contracts-1"] = CONTRACT_VERSION
    inference: Text
    framing: Text
    interpretation: Text
    validation: Text
    ranking: Text


class InferenceSnapshot(Record):
    schema_version: Literal["inference-snapshot-1"] = "inference-snapshot-1"
    project_id: UUID
    spec: InferenceSpec
    corpus: StoredCorpus
    sources: tuple[CaptureSnapshot, ...] = Field(min_length=1, max_length=1000)
    interpretation: InterpretationInput | None = None
    framing: tuple[FramingInput, ...] = Field(default=(), max_length=10000)
    candidates: tuple[CandidateInput, ...] = Field(default=(), max_length=10000)
    events: tuple[FrozenEventInput, ...] = Field(default=(), max_length=100000)
    sample_anchors: tuple[StreamRange, ...] = Field(default=(), max_length=100000)
    engines: EngineVersions

    @model_validator(mode="after")
    def consistent(self):
        if (
            self.corpus.id != self.spec.corpus_version_id
            or self.corpus.project_id != self.project_id
        ):
            raise ValueError("Corpus version or project mismatch")
        ids = unique_ids([c.id for c in self.sources])
        if set(ids) != set(self.corpus.spec.capture_ids):
            raise ValueError("Snapshot must contain every selected capture exactly once")
        unique_ids([stream.id for source in self.sources for stream in source.streams])
        owners = {}
        for source in self.sources:
            TypeAdapter(Sha256).validate_python(source.sha256)
            if source.reconstruction_sha256 is not None:
                TypeAdapter(Sha256).validate_python(source.reconstruction_sha256)
            for stream in source.streams:
                if owners.setdefault(stream.session_id, source.id) != source.id:
                    raise ValueError("Session identity cannot span different captures")
        if self.spec.interpretation_version_id != (
            self.interpretation.id if self.interpretation else None
        ):
            raise ValueError("Interpretation version is not frozen")
        if set(self.spec.framing_version_ids) != set(unique_ids([f.id for f in self.framing])):
            raise ValueError("Framing versions are not frozen")
        if set(self.spec.candidate_ids) != set(unique_ids([c.id for c in self.candidates])):
            raise ValueError("Evaluation candidate rules are not frozen")
        log_ids = {log.log_id for log in self.spec.logs}
        if any(event.log_id not in log_ids for event in self.events):
            raise ValueError("Frozen action event refers to an undeclared log")
        if len({event.id for event in self.events}) != len(self.events):
            raise ValueError("Duplicate frozen action event")
        event_logs = {event.id: event.log_id for event in self.events}
        for parameter in self.spec.parameters:
            if parameter.log_id is not None and any(
                event_logs.get(event_id) != parameter.log_id for event_id in parameter.event_ids
            ):
                raise ValueError("Parameter refers to an event outside its frozen action log")
        from protocol_lab.inference.sampling import validate_split

        validate_split(self.spec, self.sources)
        streams = {stream.id: stream for source in self.sources for stream in source.streams}
        if any(f.stream_id is not None and f.stream_id not in streams for f in self.framing):
            raise ValueError("Frozen framing stream is outside the corpus")
        for anchor in (*self.spec.excluded_ranges, *self.sample_anchors):
            stream = streams.get(anchor.stream_id)
            if (
                stream is None
                or stream.reconstruction_version != anchor.reconstruction_version
                or anchor.byte_range.end > stream.extent
            ):
                raise ValueError("Snapshot anchor is outside the frozen stream")
        if len(self.sample_anchors) > self.spec.budget.max_sample_messages:
            raise ValueError("Snapshot sample exceeds configured budget")
        identities = set()
        for anchor in self.sample_anchors:
            stream = streams[anchor.stream_id]
            capture_id = owners[stream.session_id]
            split_id = capture_id if self.spec.split.unit == "capture" else stream.session_id
            if not stream.included or split_id not in self.spec.split.discovery_ids:
                raise ValueError("Snapshot sample must contain only included discovery data")
            identity = (anchor.stream_id, anchor.byte_range.start, anchor.byte_range.end)
            if identity in identities:
                raise ValueError("Duplicate snapshot sample anchor")
            identities.add(identity)
            if any(
                excluded.stream_id == anchor.stream_id
                and excluded.byte_range.start < anchor.byte_range.end
                and anchor.byte_range.start < excluded.byte_range.end
                for excluded in self.spec.excluded_ranges
            ):
                raise ValueError("Snapshot sample overlaps excluded bytes")
        return self


class InferenceCoverage(Record):
    stream_bytes: Count
    selected_bytes: Count
    excluded_bytes: Count
    known_bytes: Count
    unavailable_bytes: Count
    ambiguous_bytes: Count
    # Overlays selected bytes; not added a second time to the partition above.
    unframed_bytes: Count

    @model_validator(mode="after")
    def partition(self):
        if (
            self.stream_bytes != self.selected_bytes + self.excluded_bytes
            or self.selected_bytes
            != self.known_bytes + self.unavailable_bytes + self.ambiguous_bytes
            or self.unframed_bytes > self.selected_bytes
        ):
            raise ValueError("Inference coverage must account for the entire selected extent")
        return self


class DetectorOutcome(Record):
    family: Family
    outcome: Literal["completed", "search_limited", "insufficient_data", "unsupported", "failed"]
    searched_units: Count
    unsearched_units: Count
    diagnostic: Text
    searched_unit: Literal[
        "rule_trial",
        "sample_message",
        "event_message_window",
        "mapping_trial",
    ] = "rule_trial"
    unsearched_unit: Literal["residual_search_space"] = "residual_search_space"


class SearchRange(Record):
    anchor: StreamRange
    scanned: bool
    diagnostic: Text


class InferenceRun(Record):
    schema_version: Literal["inference-run-1"] = "inference-run-1"
    id: UUID
    parent_id: UUID | None = None
    created_at: datetime
    snapshot: InferenceSnapshot
    outcomes: tuple[DetectorOutcome, ...] = Field(min_length=1, max_length=10)
    search_complete: bool = Field(strict=True)
    candidate_count: Count
    sample_sha256: Sha256
    coverage: InferenceCoverage
    diagnostics: tuple[Text, ...] = ()
    rule_trials: Count = 0
    semantic_sha256: Sha256 | None = None
    search_ranges: tuple[SearchRange, ...] = ()

    @model_validator(mode="after")
    def completeness(self):
        requested = {d.family for d in self.snapshot.spec.detectors}
        actual = [o.family for o in self.outcomes]
        if len(set(actual)) != len(actual) or set(actual) != requested:
            raise ValueError("Every requested detector requires exactly one outcome")
        if self.search_complete and any(
            o.outcome not in {"completed", "insufficient_data"} or o.unsearched_units
            for o in self.outcomes
        ):
            raise ValueError("Incomplete detector search cannot claim completeness")
        return self


class CandidateEvaluation(Record):
    schema_version: Literal["inference-evaluation-1"] = "inference-evaluation-1"
    id: UUID
    candidate_id: UUID
    rule_sha256: Sha256
    snapshot: InferenceSnapshot
    metrics: InferenceMetrics
    independence: Literal["independent", "exploratory", "unverified"]
    independence_reason: Text

    @model_validator(mode="after")
    def fixed_rule(self):
        frozen = {item.id: item.sha256 for item in self.snapshot.candidates}
        if (
            self.snapshot.spec.mode != "evaluate"
            or frozen.get(self.candidate_id) != self.rule_sha256
        ):
            raise ValueError("Evaluation requires a frozen candidate with the exact rule hash")
        return self


class CandidateDecision(Record):
    candidate_id: UUID
    idempotency_token: UUID
    created_at: datetime
    decision: Literal["accepted", "rejected", "deferred"]
    rationale: Text
    interpretation_version_id: UUID | None = None
    hypothesis_id: UUID | None = None


class TransformPart(Record):
    source: ByteRange
    decoded: ByteRange


class TransformMapping(Record):
    """Many-to-many encoded/decoded provenance is distinct from equal-length SourceRange."""

    anchor: StreamRange
    transform: Literal["base64_standard", "base64_urlsafe"]
    version: Literal["transform-1"] = "transform-1"
    decoded_length: Positive
    parts: tuple[TransformPart, ...] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def coverage(self):
        cursor = 0
        previous_start = self.anchor.byte_range.start
        for part in self.parts:
            if (
                part.source.start < previous_start
                or part.source.start < self.anchor.byte_range.start
                or part.source.end > self.anchor.byte_range.end
                or part.decoded.start != cursor
            ):
                raise ValueError("Transform mapping must cover decoded bytes in source order")
            previous_start, cursor = part.source.start, part.decoded.end
        if cursor != self.decoded_length:
            raise ValueError("Incomplete decoded coverage")
        return self


def canonical(record):
    data = record.model_dump(mode="json")
    if isinstance(record, ChecksumRule):
        for key in ("field_relative_to", "coverage", "coverage_start", "framing"):
            if getattr(record, key) == ChecksumRule.model_fields[key].default:
                data.pop(key)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def content_hash(record):
    return hashlib.sha256(canonical(record).encode()).hexdigest()


SCHEMAS = {
    "spec": InferenceSpec,
    "snapshot": InferenceSnapshot,
    "rule": CandidateRule,
    "candidate": InferenceCandidate,
    "run": InferenceRun,
    "evidence": CandidateEvidence,
    "evaluation": CandidateEvaluation,
    "decision": CandidateDecision,
    "transform": TransformMapping,
}


def json_schema(name="spec"):
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:protocol-lab:{CONTRACT_VERSION}:{name}",
        **TypeAdapter(SCHEMAS[name]).json_schema(),
    }
