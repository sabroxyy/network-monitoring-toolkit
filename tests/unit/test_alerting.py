from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
from pydantic import SecretStr

from netmon.alerting import AlertDispatcher, SlackNotifier, WebhookNotifier, build_notifiers
from netmon.alerting.notifiers import EmailNotifier
from netmon.config import Alerting
from netmon.metrics import Metrics
from netmon.models import Change, ChangeKind, Severity
from tests.conftest import RecordingNotifier

CRIT = Change(ChangeKind.PORT_OPENED, "192.0.2.10", Severity.CRITICAL, "rdp open", 3389, "tcp")
INFO = Change(ChangeKind.PORT_CLOSED, "192.0.2.10", Severity.INFO, "closed", 80, "tcp")


def mock_client(log: list[httpx.Request], status: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        log.append(request)
        return httpx.Response(status)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_webhook_is_hmac_signed() -> None:
    reqs: list[httpx.Request] = []
    async with mock_client(reqs) as client:
        n = WebhookNotifier("https://hooks.example.test/x", client, SecretStr("k"), {"X-A": "1"})
        await n.send("lab", [CRIT])
    (req,) = reqs
    body = req.content
    ts = req.headers["X-Netmon-Timestamp"]
    expected = hmac.new(b"k", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert req.headers["X-Netmon-Signature"] == f"sha256={expected}"
    assert req.headers["X-A"] == "1"
    data = json.loads(body)
    assert data["job"] == "lab" and data["changes"][0]["port"] == 3389


async def test_slack_payload_and_http_errors() -> None:
    reqs: list[httpx.Request] = []
    async with mock_client(reqs) as client:
        await SlackNotifier(SecretStr("https://hooks.slack.test/T/B/X"), client).send("lab", [CRIT])
    assert "rdp open" in json.loads(reqs[0].content)["text"]

    async with mock_client([], status=500) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await SlackNotifier(SecretStr("https://hooks.slack.test/x"), client).send("lab", [CRIT])


async def test_dispatcher_filters_severity_and_cooldown() -> None:
    clock = [0.0]
    rec = RecordingNotifier()
    d = AlertDispatcher([rec], Severity.WARNING, cooldown=60, clock=lambda: clock[0])
    assert await d.dispatch("lab", [CRIT, INFO]) == [CRIT]
    assert await d.dispatch("lab", [CRIT]) == []  # suppressed within cooldown
    clock[0] = 61
    assert await d.dispatch("lab", [CRIT]) == [CRIT]
    assert len(rec.sent) == 2


async def test_dispatcher_survives_channel_failure() -> None:
    class Broken:
        name = "broken"

        async def send(self, job: str, changes: object) -> None:
            raise RuntimeError("down")

    rec, metrics = RecordingNotifier(), Metrics()
    d = AlertDispatcher([Broken(), rec], metrics=metrics, attempts=1)
    assert await d.dispatch("lab", [CRIT]) == [CRIT]
    assert rec.sent
    failed = metrics.registry.get_sample_value(
        "netmon_alerts_total", {"channel": "broken", "result": "failed"}
    )
    assert failed == 1


def test_email_message_build() -> None:
    n = EmailNotifier("smtp.example.test", 587, "netmon@example.test", ["soc@example.test"])
    msg = n._build("lab", [INFO, CRIT])
    assert msg["Subject"] == "[netmon][CRITICAL] 2 change(s) in lab"
    assert "rdp open" in msg.get_content()


async def test_build_notifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLACK_URL", "https://hooks.slack.test/x")
    cfg = Alerting.model_validate(
        {
            "channels": [
                {"type": "slack", "webhook_url_ref": "env:SLACK_URL"},
                {"type": "webhook", "url": "https://siem.example.test/ingest"},
                {
                    "type": "email",
                    "smtp_host": "smtp.example.test",
                    "sender": "a@example.test",
                    "recipients": ["b@example.test"],
                },
            ]
        }
    )
    async with httpx.AsyncClient() as client:
        names = [n.name for n in build_notifiers(cfg, client)]
    assert names == ["slack", "webhook", "email"]


def test_webhook_requires_https() -> None:
    with pytest.raises(ValueError, match="https"):
        Alerting.model_validate({"channels": [{"type": "webhook", "url": "http://evil.test"}]})
