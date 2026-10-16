"""Launcher checks do not touch the research database or require Docker."""

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "launcher", Path(__file__).resolve().parents[2] / "run.py"
)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def test_configuration_preserves_existing_credentials(tmp_path):
    (tmp_path / ".env.example").write_text("PASSWORD=CHANGE_ME\nURL=CHANGE_ME\n")
    launcher.configure(tmp_path)
    original = (tmp_path / ".env").read_text()
    values = [line.split("=", 1)[1] for line in original.splitlines()]
    assert values[0] == values[1]
    assert len(values[0]) == 48
    launcher.configure(tmp_path)
    assert (tmp_path / ".env").read_text() == original


def test_busy_port_is_rejected():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        with pytest.raises(RuntimeError, match="busy"):
            launcher.check_port(sock.getsockname()[1])


def test_server_failure_is_detected():
    process = launcher.start([sys.executable, "-c", "raise SystemExit(7)"])
    process.wait(timeout=10)
    with pytest.raises(RuntimeError, match="exited during startup"):
        launcher.wait_ready("http://127.0.0.1:1", [process])


def test_stop_terminates_child():
    process = launcher.start([sys.executable, "-c", "import time; time.sleep(60)"])
    launcher.stop(process)
    assert process.poll() is not None
