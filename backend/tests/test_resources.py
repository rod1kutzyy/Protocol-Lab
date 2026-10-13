"""Configurable protective budgets fail explicitly and never publish CLI output."""

import io
import json
from dataclasses import fields
from pathlib import Path

import pytest

from protocol_lab.cli.main import main
from protocol_lab.interpretation.schema import ProtocolModel
from protocol_lab.services.application import apply_capture
from protocol_lab.services.resources import ResultBudget, ResultLimits
from protocol_lab.services.settings import Settings

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


@pytest.mark.parametrize("name", [f.name for f in fields(Settings) if f.name.startswith("max_")])
@pytest.mark.parametrize("value", [0, -1])
def test_settings_reject_invalid_limits(name, value):
    with pytest.raises(ValueError, match=name):
        Settings(**{name: value})


def test_environment_loads_worker_and_output_limits(tmp_path, monkeypatch):
    keys = {
        "MAX_WORKERS": 1,
        "MAX_JOBS": 12,
        "MAX_VALIDATION_RESULTS": 17,
        "MAX_VALIDATION_BYTES": 4096,
        "MAX_INTERPRETATION_BYTES": 2048,
    }
    for key, value in keys.items():
        monkeypatch.setenv("PROTOCOL_LAB_" + key, str(value))
    settings = Settings.environment(tmp_path / ".env")
    assert settings.max_workers == 1 and settings.max_jobs == 12
    assert settings.validation_limits == ResultLimits(17, 4096)
    assert settings.max_interpretation_bytes == 2048


def test_budget_counts_utf8_bytes_and_all_diagnostic_rows():
    budget = ResultBudget(ResultLimits(2, 5))
    budget.consume("я\n")  # 3 UTF-8 bytes, rather than 2 characters
    budget.consume("ab")
    with pytest.raises(ValueError, match="rows 3/2, bytes 6/5"):
        budget.consume("c")


def test_cli_limit_refuses_partial_output_and_preserves_existing_files(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("PROTOCOL_LAB_MAX_VALIDATION_RESULTS", "1")
    output = tmp_path / "results.json"
    sentinel = tmp_path / "keep.json"
    sentinel.write_text("existing research")
    assert (
        main(
            [
                "apply",
                "--model",
                str(FIXTURES / "cli/length-model.json"),
                "--capture",
                str(FIXTURES / "framing/length-big.pcap"),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert "configured limits" in capsys.readouterr().err
    assert not output.exists()
    assert sentinel.read_text() == "existing research"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.json"]


@pytest.mark.parametrize(
    "name",
    [
        "framing/length-big.pcap",
        "tcp/gaps-overlaps.pcap",
        "tcp/reused-tuple.pcap",
        "multi-interface.pcapng",
    ],
)
def test_identical_inputs_repeat_all_facts_and_source_ranges(name):
    model = ProtocolModel.model_validate_json((FIXTURES / "cli/length-model.json").read_text())
    documents = []
    for _ in range(2):
        output = io.StringIO()
        apply_capture(model, FIXTURES / name, output)
        data = json.loads(output.getvalue())
        # Execution times are run metadata, not evidence or parser results.
        data["run"]["snapshot"].pop("created_at")
        data["run"]["snapshot"]["corpus"].pop("created_at")
        documents.append(data)
    assert documents[0] == documents[1]
