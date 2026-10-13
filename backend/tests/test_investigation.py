import json
from decimal import Decimal, localcontext
from uuid import UUID

import pytest

from protocol_lab.capture.index import WorkCancelled
from protocol_lab.research.action_logs import (
    LogError,
    LogMapping,
    log_rows,
    parse_events,
    timestamp_ns,
)
from protocol_lab.research.search import search_known


def test_time_formats_keep_exact_nanos_and_timezone():
    expected = "1700000000000126123"
    assert timestamp_ns("2023-11-14T22:13:20.000126123Z", "iso8601") == expected
    assert timestamp_ns("2023-11-15T01:13:20.000126123+03:00", "iso8601") == expected
    assert timestamp_ns(Decimal("1700000000.000126123"), "unix_s") == expected
    assert timestamp_ns("1700000000000.126123", "unix_ms") == expected
    assert timestamp_ns(expected, "unix_ns") == expected
    assert timestamp_ns("1969-12-31T23:59:59.500Z", "iso8601") == "-500000000"


@pytest.mark.parametrize(
    "value,format",
    [
        ("2023-11-14T22:13:20", "iso8601"),
        ("NaN", "unix_s"),
        ("1.0000000001", "unix_s"),
        ("1.00000000000000000000000000001", "unix_s"),
        ("1.00000000000000000000000000001", "unix_ms"),
        ("1.00000000000000000000000000001", "unix_ns"),
        ("1e-100000", "unix_s"),
        ("1e10000", "unix_ns"),
        ("9223372036854775808", "unix_ns"),
    ],
)
def test_invalid_precision_timezone_and_range_are_explicit(value, format):
    with pytest.raises(ValueError):
        timestamp_ns(value, format)


def test_csv_mapping_diagnostics_and_quoted_parameters():
    data = b'when;action;params\n1.000000001;Send;"a;b"\nbad;Broken;0\n'
    mapping = LogMapping(
        timestamp_field="when",
        label_field="action",
        parameters_field="params",
        timestamp_format="unix_s",
        delimiter=";",
    )
    events, summary = parse_events(UUID(int=1), data, "csv", mapping)
    assert events[0].timestamp_ns == "1000000001"
    assert events[0].parameters_json == '"a;b"'
    assert events[0].row_index == 1
    assert summary["rejected_rows"] == 1 and summary["diagnostics"][0]["row_index"] == 2
    assert parse_events(UUID(int=1), data, "csv", mapping)[0] == events


def test_json_decimal_time_is_not_rounded_and_bad_row_does_not_hide_good():
    data = b'[{"t":1700000000.000126123,"a":"Send"},{"t":null,"a":"Bad"}]'
    events, summary = parse_events(
        UUID(int=1),
        data,
        "json",
        LogMapping(timestamp_field="t", label_field="a", timestamp_format="unix_s"),
    )
    assert events[0].timestamp_ns == "1700000000000126123"
    assert summary["event_count"] == 1 and summary["rejected_rows"] == 1


def test_json_parameters_keep_nested_numeric_types_and_exact_values():
    data = b"""[{"t":1700000000.000126123,"a":"Send","p":{
        "speed":1.5,"count":2,"nested":[-0.125,1.2345678901234567890123456789,
        {"text":"1.5","enabled":true,"empty":null,"exponent":1e-30}]}}]"""
    events, summary = parse_events(
        UUID(int=1),
        data,
        "json",
        LogMapping(
            timestamp_field="t", label_field="a", parameters_field="p", timestamp_format="unix_s"
        ),
    )
    assert summary["rejected_rows"] == 0
    assert events[0].timestamp_ns == "1700000000000126123"
    parameters = json.loads(events[0].parameters_json, parse_float=Decimal)
    assert parameters == {
        "speed": Decimal("1.5"),
        "count": 2,
        "nested": [
            Decimal("-0.125"),
            Decimal("1.2345678901234567890123456789"),
            {"text": "1.5", "enabled": True, "empty": None, "exponent": Decimal("1e-30")},
        ],
    }


def test_epoch_scaling_is_independent_of_decimal_context():
    with localcontext() as context:
        context.prec = 6
        assert timestamp_ns("1700000000.000126123", "unix_s") == "1700000000000126123"
        assert timestamp_ns("1.00000000000000000000000000000", "unix_s") == "1000000000"
        with pytest.raises(ValueError, match="precision"):
            timestamp_ns("1.00000000000000000000000000001", "unix_s")


def test_log_errors_and_cancellation():
    for data, format in [
        (b"t,t\n1,2", "csv"),
        (b"{}", "json"),
        (b'[ {"t": NaN} ]', "json"),
        (b"\xff", "csv"),
    ]:
        with pytest.raises(LogError):
            log_rows(data, format)
    with pytest.raises(LogError, match="Mapped field"):
        parse_events(
            UUID(int=1), b"a,b\n1,2", "csv", LogMapping(timestamp_field="x", label_field="b")
        )
    with pytest.raises(WorkCancelled):
        parse_events(
            UUID(int=1),
            b"a,b\n1,X",
            "csv",
            LogMapping(timestamp_field="a", label_field="b"),
            lambda: True,
        )


def test_search_crosses_known_packet_and_page_boundaries_but_not_unknown_ranges():
    chunks = [(0, 2, b"AB"), (2, 5, b"ABA"), (5, 8, None), (8, 12, b"BABA")]
    result = search_known(chunks, b"ABA")
    assert result["matches"] == [0, 2, 9]
    assert result["skipped_bytes"] == 3 and result["skipped_ranges"] == [[5, 8]]
    assert search_known([(0, 2, b"AB"), (2, 3, None), (3, 4, b"A")], b"ABA")["matches"] == []


def test_search_overlapping_matches_resume_and_single_byte():
    chunks = [(0, 2, b"AA"), (2, 6, b"AAAA")]
    result = search_known(chunks, b"AAA", max_matches=2)
    assert result["matches"] == [0, 1] and not result["complete"]
    assert search_known(chunks, b"AAA", start=result["next_offset"])["matches"] == [2, 3]
    assert search_known(chunks, b"A", start=4)["matches"] == [4, 5]


def test_search_cancellation_and_pattern_limits():
    with pytest.raises(WorkCancelled):
        search_known([(0, 3, b"ABC")], b"A", cancelled=lambda: True)
    with pytest.raises(ValueError):
        search_known([], b"")
