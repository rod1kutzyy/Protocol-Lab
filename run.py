#!/usr/bin/env python3
"""Cross-platform local launcher. First run: python run.py --setup."""

import argparse
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def executable(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(
            f"Install {name} and add it to PATH before running this script."
        )
    return path


def run(command, cwd=ROOT):
    subprocess.run([str(item) for item in command], cwd=cwd, check=True)


def ensure_docker(docker):
    """Start Docker Desktop on Windows and wait for the Docker engine."""
    def engine_ready():
        try:
            subprocess.run(
                [docker, "info", "--format", "{{.ServerVersion}}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    if engine_ready():
        return

    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", "C:/Program Files"))
            / "Docker/Docker/Docker Desktop.exe",
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs/Docker/Docker/Docker Desktop.exe",
        ]
        desktop = next((path for path in candidates if path.is_file()), None)
        if desktop is None:
            raise RuntimeError(
                "Docker Desktop is installed incompletely or not found. "
                "Install it, start it, wait for 'Engine running', then retry."
            )
        print("Starting Docker Desktop; waiting for its engine...", flush=True)
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen([str(desktop)], creationflags=flags)
    else:
        raise RuntimeError(
            "Docker is installed, but its engine is not running. Start Docker "
            "(for example, `sudo systemctl start docker`) and run this command again."
        )

    deadline = time.monotonic() + 180
    next_message = time.monotonic() + 10
    while time.monotonic() < deadline:
        if engine_ready():
            print("Docker engine is ready.", flush=True)
            return
        if time.monotonic() >= next_message:
            print("Still waiting for Docker Desktop to finish starting...", flush=True)
            next_message = time.monotonic() + 10
        time.sleep(2)
    raise RuntimeError(
        "Docker Desktop did not start within 3 minutes. Open Docker Desktop, "
        "wait until it says 'Engine running', then retry."
    )


def configure(root):
    """Create credentials only for a new installation; never rewrite user settings."""
    destination = root / ".env"
    if destination.exists():
        return
    content = (root / ".env.example").read_text(encoding="utf-8")
    content = content.replace("CHANGE_ME", secrets.token_hex(24))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
    print("Created .env with a random local database password.", flush=True)


def check_port(port):
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            raise RuntimeError(
                f"Port {port} is busy. Stop the other server and retry."
            ) from None


def start(command, cwd=ROOT, env=None):
    options = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    return subprocess.Popen(
        [str(item) for item in command], cwd=cwd, env=env, **options
    )


def stop(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def wait_ready(url, processes, timeout=60):
    # Local health checks must not be routed through a user's HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("A server exited during startup; see its output above.")
        try:
            with opener.open(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Server did not become ready within {timeout}s: {url}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Install locked dependencies (needs network)",
    )
    parser.add_argument(
        "--external-db",
        action="store_true",
        help="Use configured PostgreSQL; skip Docker",
    )
    args = parser.parse_args()
    processes = []
    try:
        node = executable("node")
        version = (
            subprocess.check_output([node, "--version"], text=True).strip().lstrip("v")
        )
        if tuple(map(int, version.split(".")[:2])) < (22, 12):
            raise RuntimeError("Node.js 22.12 or newer is required.")
        docker = None if args.external_db else executable("docker")
        python = (
            ROOT
            / "backend/.venv"
            / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        )
        vite = ROOT / "frontend/node_modules/vite/bin/vite.js"
        check_port(8000)
        check_port(5173)
        if args.setup:
            uv = executable("uv")
            npm = executable("npm.cmd" if os.name == "nt" else "npm")
            run([uv, "sync", "--project", ROOT / "backend", "--frozen"])
            run([npm, "ci"], cwd=ROOT / "frontend")
        if not python.exists() or not vite.exists():
            raise RuntimeError(
                "Dependencies are missing. Run this script with --setup first."
            )
        if args.external_db:
            if not (ROOT / ".env").exists() and not os.environ.get(
                "PROTOCOL_LAB_DATABASE_URL"
            ):
                raise RuntimeError(
                    "Set PROTOCOL_LAB_DATABASE_URL in .env or the environment."
                )
        else:
            configure(ROOT)
            ensure_docker(docker)
            run(
                [
                    docker,
                    "compose",
                    "-f",
                    ROOT / "docker-compose.yml",
                    "up",
                    "-d",
                    "--wait",
                    "--wait-timeout",
                    "90",
                    "--pull",
                    "missing" if args.setup else "never",
                    "postgres",
                ]
            )
        print("Applying database migrations...", flush=True)
        run(
            [
                python,
                "-m",
                "alembic",
                "-c",
                ROOT / "backend/alembic.ini",
                "upgrade",
                "head",
            ]
        )
        processes.append(
            start(
                [
                    python,
                    "-m",
                    "uvicorn",
                    "protocol_lab.api.app:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8000",
                ]
            )
        )
        wait_ready("http://127.0.0.1:8000/api/v1/health", processes)
        processes.append(
            start(
                [node, vite, "--host", "127.0.0.1", "--port", "5173", "--strictPort"],
                cwd=ROOT / "frontend",
                env={**os.environ, "PROTOCOL_LAB_API_URL": "http://127.0.0.1:8000"},
            )
        )
        wait_ready("http://127.0.0.1:5173", processes)
        print(
            "\nProtocol Lab: http://127.0.0.1:5173\nAPI: http://127.0.0.1:8000/docs\n"
            "Press Ctrl+C to stop. PostgreSQL is left running; data is preserved.",
            flush=True,
        )
        while True:
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f"Server exited (code {process.returncode}).")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping Protocol Lab...", flush=True)
        return 0
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"Launch failed: {exc}", file=sys.stderr)
        return 1
    finally:
        for process in reversed(processes):
            stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
