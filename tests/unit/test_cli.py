from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from netmon.cli import main
from netmon.logging_setup import JsonFormatter, redact


def write_config(tmp_path: Path, **extra: object) -> Path:
    cfg = {
        "database": f"sqlite:///{tmp_path}/netmon.db",
        "policy": {
            "allowed_networks": ["192.0.2.0/24"],
            "authorization": {"owner": "netops", "reference": "CHG-1"},
        },
        "jobs": [{"name": "lab", "targets": ["192.0.2.0/29"], "profile": "services"}],
        "logging": {"json": False},
        **extra,
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def test_validate_prints_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-c", str(write_config(tmp_path)), "validate"]) == 0
    out = capsys.readouterr().out
    assert "[ok] lab" in out and "nmap -oX - --noninteractive" in out


def test_validate_reports_out_of_scope(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_config(tmp_path, jobs=[{"name": "x", "targets": ["10.0.0.1"]}])
    assert main(["-c", str(path), "validate"]) == 1
    assert "outside allowed_networks" in capsys.readouterr().err


def test_bad_config_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-c", str(tmp_path / "nope.yaml"), "validate"]) == 2


def test_migrate_and_queries(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = str(write_config(tmp_path))
    assert main(["-c", path, "migrate"]) == 0
    assert "applied migrations: [1]" in capsys.readouterr().out
    assert main(["-c", path, "migrate"]) == 0
    assert "up to date" in capsys.readouterr().out
    for cmd in (["hosts"], ["changes"], ["scans", "--job", "lab"], ["history", "192.0.2.1"]):
        assert main(["-c", path, *cmd]) == 0
        assert capsys.readouterr().out.strip() == "[]"


def test_redaction() -> None:
    assert "abc" not in redact("posting to https://hooks.slack.com/services/T0/B0/abc")
    assert redact("token=hunter2 other") == "token=*** other"
    import logging

    rec = logging.LogRecord("x", logging.INFO, "f", 1, "password: p4ss", None, None)
    assert "p4ss" not in JsonFormatter().format(rec)


def test_scan_refuses_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert main(["-c", str(write_config(tmp_path)), "scan"]) == 2
    assert "refusing to run as root" in capsys.readouterr().err
