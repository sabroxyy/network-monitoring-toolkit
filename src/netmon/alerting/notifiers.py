"""Alert channels. Each notifier sends one batched message per scan."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
import ssl
import time
from collections.abc import Sequence
from dataclasses import asdict
from email.message import EmailMessage
from typing import Any, Protocol

import httpx
from pydantic import SecretStr

from netmon.models import Change

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "warning": ":large_orange_circle:",
    "info": ":white_circle:",
}
_MAX_LINES = 50


class Notifier(Protocol):
    name: str

    async def send(self, job: str, changes: Sequence[Change]) -> None: ...


def _lines(changes: Sequence[Change]) -> list[str]:
    out = [f"[{c.severity.value.upper()}] {c.message}" for c in changes[:_MAX_LINES]]
    if len(changes) > _MAX_LINES:
        out.append(f"... and {len(changes) - _MAX_LINES} more")
    return out


def payload(job: str, changes: Sequence[Change]) -> dict[str, Any]:
    return {
        "source": "netmon",
        "job": job,
        "count": len(changes),
        "changes": [asdict(c) for c in changes],
    }


class SlackNotifier:
    name = "slack"

    def __init__(self, webhook_url: SecretStr, client: httpx.AsyncClient) -> None:
        self._url = webhook_url
        self._client = client

    async def send(self, job: str, changes: Sequence[Change]) -> None:
        text = "\n".join(
            f"{_SEVERITY_EMOJI.get(c.severity.value, '')} {c.message}" for c in changes[:_MAX_LINES]
        )
        body = {"text": f"*netmon* — {len(changes)} change(s) in job `{job}`\n{text}"}
        resp = await self._client.post(self._url.get_secret_value(), json=body)
        resp.raise_for_status()


class WebhookNotifier:
    """POSTs JSON. With a secret, signs ``<timestamp>.<body>`` using HMAC-SHA256.

    Receivers should verify ``X-Netmon-Signature`` and reject stale timestamps (replay).
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        client: httpx.AsyncClient,
        secret: SecretStr | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url
        self._client = client
        self._secret = secret
        self._headers = headers or {}

    async def send(self, job: str, changes: Sequence[Change]) -> None:
        body = json.dumps(payload(job, changes), separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json", **self._headers}
        if self._secret is not None:
            ts = str(int(time.time()))
            sig = hmac.new(
                self._secret.get_secret_value().encode(), ts.encode() + b"." + body, hashlib.sha256
            ).hexdigest()
            headers |= {"X-Netmon-Timestamp": ts, "X-Netmon-Signature": f"sha256={sig}"}
        resp = await self._client.post(self._url, content=body, headers=headers)
        resp.raise_for_status()


class EmailNotifier:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        *,
        starttls: bool = True,
        username: SecretStr | None = None,
        password: SecretStr | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._host, self._port = host, port
        self._sender, self._recipients = sender, recipients
        self._starttls = starttls
        self._username, self._password = username, password
        self._timeout = timeout

    def _build(self, job: str, changes: Sequence[Change]) -> EmailMessage:
        msg = EmailMessage()
        worst = max((c.severity for c in changes), key=["info", "warning", "critical"].index)
        msg["Subject"] = f"[netmon][{worst.upper()}] {len(changes)} change(s) in {job}"
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg.set_content("\n".join(_lines(changes)))
        return msg

    def _send_sync(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            if self._starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self._username and self._password:
                smtp.login(self._username.get_secret_value(), self._password.get_secret_value())
            smtp.send_message(msg)

    async def send(self, job: str, changes: Sequence[Change]) -> None:
        await asyncio.to_thread(self._send_sync, self._build(job, changes))
