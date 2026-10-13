from protocol_lab.services.settings import Settings


def clear_settings(monkeypatch):
    for key in (
        "DATABASE_URL",
        "PROJECT_ROOT",
        "MAX_UPLOAD_BYTES",
        "MAX_BLOCK_BYTES",
        "MAX_PACKETS",
    ):
        monkeypatch.delenv("PROTOCOL_LAB_" + key, raising=False)


def test_dotenv_loads_without_export_or_shell_execution(tmp_path, monkeypatch):
    clear_settings(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text(
        'PROTOCOL_LAB_DATABASE_URL="postgresql://user:pass@127.0.0.1/lab"\n'
        "PROTOCOL_LAB_PROJECT_ROOT=./research\nPROTOCOL_LAB_MAX_PACKETS=42\n"
        "IGNORED=$(touch should-not-exist)\n"
    )
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    settings = Settings.environment(env_file)
    assert settings.database_url == "postgresql://user:pass@127.0.0.1/lab"
    assert settings.project_root == tmp_path / "research"
    assert settings.max_packets == 42
    assert not (elsewhere / "should-not-exist").exists()
    import os

    assert "PROTOCOL_LAB_DATABASE_URL" not in os.environ


def test_exported_environment_overrides_dotenv(tmp_path, monkeypatch):
    clear_settings(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PROTOCOL_LAB_DATABASE_URL=postgresql://file\nPROTOCOL_LAB_MAX_PACKETS=10\n"
    )
    monkeypatch.setenv("PROTOCOL_LAB_DATABASE_URL", "postgresql://environment")
    monkeypatch.setenv("PROTOCOL_LAB_MAX_PACKETS", "20")
    settings = Settings.environment(env_file)
    assert settings.database_url == "postgresql://environment"
    assert settings.max_packets == 20


def test_missing_dotenv_keeps_defaults(tmp_path, monkeypatch):
    clear_settings(monkeypatch)
    settings = Settings.environment(tmp_path / ".env")
    assert settings.database_url is None
    assert settings.project_root == tmp_path / "projects"
    assert settings.max_packets == 1_000_000


def test_alembic_reads_same_dotenv_without_export(tmp_path, monkeypatch):
    from io import StringIO
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    clear_settings(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("PROTOCOL_LAB_DATABASE_URL=postgresql+psycopg://local@127.0.0.1/lab\n")
    loader = Settings.environment
    monkeypatch.setattr(Settings, "environment", classmethod(lambda cls: loader(env_file)))
    output = StringIO()
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"), output_buffer=output)
    # Offline SQL generation verifies the migration loader without touching any database.
    command.upgrade(config, "head", sql=True)
    assert "CREATE TABLE projects" in output.getvalue()
    assert "CREATE TABLE action_logs" in output.getvalue()
