"""End-to-end: real nmap against a throwaway HTTP server on 127.0.0.1.

Skipped automatically when nmap is not installed. Uses only unprivileged TCP connect
scans against loopback, so it is safe to run on any developer machine or CI runner.
"""

from __future__ import annotations

import shutil
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from netmon.alerting import AlertDispatcher
from netmon.cli import main
from netmon.metrics import Metrics
from netmon.models import ChangeKind, ScanStatus
from netmon.scanner import NmapRunner
from netmon.service import Monitor
from netmon.storage.sqlite import SQLiteStorage
from tests.conftest import RecordingNotifier, make_settings

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed"),
]


class _Quiet(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def http_port() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def test_real_scan_detects_new_port(http_port: int) -> None:
    closed = _free_port()
    settings = make_settings(
        jobs=[
            {
                "name": "loopback",
                "targets": ["127.0.0.1"],
                "profile": "services",
                "ports": f"{closed}",
                "timeout": "2m",
                "timing": 4,
            }
        ]
    )
    storage = SQLiteStorage(":memory:")
    await storage.migrate()
    rec, metrics = RecordingNotifier(), Metrics()
    monitor = Monitor(
        settings, storage, NmapRunner(), AlertDispatcher([rec], metrics=metrics), metrics
    )

    first = await monitor.run_job(settings.job("loopback"))
    assert first.status is ScanStatus.SUCCEEDED, first.reason
    assert (await storage.load_state("loopback"))["127.0.0.1"].open_services() == {}

    # Same job, now including the live HTTP port -> should report PORT_OPENED.
    job = settings.job("loopback").model_copy(update={"ports": f"{closed},{http_port}"})
    second = await monitor.run_job(job)
    assert second.status is ScanStatus.SUCCEEDED, second.reason
    (change,) = second.changes
    assert change.kind is ChangeKind.PORT_OPENED and change.port == http_port
    assert rec.sent and rec.sent[0][1][0].port == http_port


def test_cli_scan_loopback(
    tmp_path: Path, http_port: int, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = {
        "database": f"sqlite:///{tmp_path}/netmon.db",
        "allow_root": True,  # CI containers often run as root; production must not
        "policy": {
            "allowed_networks": ["127.0.0.0/8"],
            "authorization": {"owner": "ci", "reference": "TEST"},
        },
        "jobs": [{"name": "lo", "targets": ["127.0.0.1"], "ports": str(http_port), "timing": 4}],
        "metrics": {"enabled": False},
        "logging": {"json": False, "level": "WARNING"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    assert main(["-c", str(path), "scan", "--job", "lo"]) == 0
    assert "lo: succeeded" in capsys.readouterr().out
    assert main(["-c", str(path), "hosts"]) == 0
    assert '"address": "127.0.0.1"' in capsys.readouterr().out
