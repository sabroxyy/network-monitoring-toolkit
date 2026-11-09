from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from netmon.alerting import AlertDispatcher
from netmon.config import Settings
from netmon.metrics import Metrics
from netmon.models import Change
from netmon.service import Monitor
from netmon.storage.sqlite import SQLiteStorage

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_xml(name: str) -> str:
    return (FIXTURES / name).read_text()


def make_settings(**overrides: Any) -> Settings:
    raw: dict[str, Any] = {
        "database": "sqlite:///:memory:",
        "policy": {
            "allowed_networks": ["192.0.2.0/24", "127.0.0.0/8"],
            "max_concurrent_scans": 2,
            "max_rate": 200,
            "authorization": {"owner": "netops", "reference": "CHG-1"},
        },
        "jobs": [{"name": "lab", "targets": ["192.0.2.0/29"], "profile": "services"}],
        "metrics": {"enabled": False},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(raw.get(key), dict):
            raw[key] = {**raw[key], **value}
        else:
            raw[key] = value
    return Settings.model_validate(raw)


class FakeRunner:
    """Returns queued XML documents (or raises queued exceptions) in order."""

    def __init__(self, *outputs: str | BaseException) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[str]] = []

    async def run(self, argv: list[str], timeout: float) -> str:
        self.calls.append(argv)
        out = self.outputs.pop(0)
        if isinstance(out, BaseException):
            raise out
        return out


class RecordingNotifier:
    name = "recording"

    def __init__(self) -> None:
        self.sent: list[tuple[str, list[Change]]] = []

    async def send(self, job: str, changes: Any) -> None:
        self.sent.append((job, list(changes)))


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """CLI tests call configure_logging(); don't leak handlers into other tests."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
async def storage() -> AsyncIterator[SQLiteStorage]:
    s = SQLiteStorage(":memory:")
    await s.migrate()
    yield s
    await s.close()


@pytest.fixture
def notifier() -> RecordingNotifier:
    return RecordingNotifier()


@pytest.fixture
def monitor_factory(storage: SQLiteStorage, notifier: RecordingNotifier) -> Callable[..., Monitor]:
    def build(runner: FakeRunner, settings: Settings | None = None) -> Monitor:
        metrics = Metrics()
        return Monitor(
            settings or make_settings(),
            storage,
            runner,
            AlertDispatcher([notifier], metrics=metrics),
            metrics,
            retry_base_delay=0,
        )

    return build
