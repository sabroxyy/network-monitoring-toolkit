from __future__ import annotations

from datetime import UTC, datetime, time
from pathlib import Path

import pytest
from pydantic import ValidationError

from netmon.config import (
    ConfigError,
    Job,
    ScanWindow,
    load_settings,
    parse_duration,
    resolve_secret,
)
from tests.conftest import make_settings

EXAMPLE = Path(__file__).parents[2] / "config" / "config.example.yaml"


@pytest.mark.parametrize(
    ("value", "seconds"),
    [(90, 90), ("90", 90), ("30s", 30), ("15m", 900), ("2h", 7200), ("1d", 86400)],
)
def test_parse_duration(value: object, seconds: int) -> None:
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("bad", ["", "5w", "-1m", True, None])
def test_parse_duration_rejects(bad: object) -> None:
    with pytest.raises(ValueError):
        parse_duration(bad)


def test_job_durations_and_defaults() -> None:
    job = Job(name="a", targets=["10.0.0.0/24"], interval="15m", ports="22,80")
    assert job.interval == 900
    assert job.top_ports is None  # explicit ports override top_ports


@pytest.mark.parametrize(
    "target", ["-iL /etc/shadow", "10.0.0.1; rm -rf /", "$(id)", "a b", "--script=x"]
)
def test_job_rejects_injection_targets(target: str) -> None:
    with pytest.raises(ValidationError):
        Job(name="a", targets=[target])


def test_job_rejects_bad_ports_and_t5() -> None:
    with pytest.raises(ValidationError):
        Job(name="a", targets=["10.0.0.1"], ports="22 -oN /tmp/x")
    with pytest.raises(ValidationError):
        Job(name="a", targets=["10.0.0.1"], timing=5)


def test_policy_rejects_overly_broad_network() -> None:
    with pytest.raises(ValidationError, match="too broad"):
        make_settings(policy={"allowed_networks": ["0.0.0.0/0"]})


def test_duplicate_job_names() -> None:
    with pytest.raises(ValidationError, match="duplicate"):
        make_settings(jobs=[{"name": "x", "targets": ["192.0.2.1"]}] * 2)


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(typo_key=1)


def test_resolve_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NETMON_TEST_SECRET", "s3cret")
    assert resolve_secret("env:NETMON_TEST_SECRET").get_secret_value() == "s3cret"  # type: ignore[union-attr]
    f = tmp_path / "secret"
    f.write_text("from-file\n")
    assert resolve_secret(f"file:{f}").get_secret_value() == "from-file"  # type: ignore[union-attr]
    assert resolve_secret(None) is None
    with pytest.raises(ConfigError, match="no inline secrets"):
        resolve_secret("https://hooks.slack.com/services/abc")
    with pytest.raises(ConfigError, match="not set"):
        resolve_secret("env:NETMON_DEFINITELY_UNSET")


def test_scan_window_simple_and_overnight() -> None:
    biz = ScanWindow(days=["mon", "tue", "wed", "thu", "fri"], start=time(9), end=time(17))
    assert biz.contains(datetime(2026, 11, 9, 10, tzinfo=UTC))  # Monday
    assert not biz.contains(datetime(2026, 11, 8, 10, tzinfo=UTC))  # Sunday
    assert not biz.contains(datetime(2026, 11, 9, 17, tzinfo=UTC))  # end is exclusive

    night = ScanWindow(days=["fri"], start=time(22), end=time(6))
    assert night.contains(datetime(2026, 11, 13, 23, tzinfo=UTC))  # Fri 23:00
    assert night.contains(datetime(2026, 11, 14, 5, tzinfo=UTC))  # Sat 05:00 (Fri window)
    assert not night.contains(datetime(2026, 11, 15, 5, tzinfo=UTC))  # Sun 05:00


def test_scan_window_timezone() -> None:
    w = ScanWindow(start=time(1), end=time(5), timezone="America/New_York")
    assert w.contains(datetime(2026, 11, 9, 7, tzinfo=UTC))  # 02:00 EST
    assert not w.contains(datetime(2026, 11, 9, 3, tzinfo=UTC))  # 22:00 EST


def test_example_config_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings(EXAMPLE)
    assert settings.jobs


def test_load_settings_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("- a list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_settings(bad)
