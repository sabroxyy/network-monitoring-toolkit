"""Severity filtering, de-duplication (cooldown) and resilient fan-out."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence

import httpx

from netmon.alerting.notifiers import EmailNotifier, Notifier, SlackNotifier, WebhookNotifier
from netmon.config import (
    Alerting,
    ConfigError,
    EmailChannel,
    SlackChannel,
    WebhookChannel,
    resolve_secret,
)
from netmon.metrics import Metrics
from netmon.models import Change, Severity
from netmon.retry import retry_async

log = logging.getLogger(__name__)
_ORDER = [Severity.INFO, Severity.WARNING, Severity.CRITICAL]


def build_notifiers(cfg: Alerting, client: httpx.AsyncClient) -> list[Notifier]:
    notifiers: list[Notifier] = []
    for ch in cfg.channels:
        if isinstance(ch, SlackChannel):
            url = resolve_secret(ch.webhook_url_ref)
            if url is None:
                raise ConfigError("slack channel requires webhook_url_ref")
            notifiers.append(SlackNotifier(url, client))
        elif isinstance(ch, WebhookChannel):
            notifiers.append(
                WebhookNotifier(ch.url, client, resolve_secret(ch.hmac_secret_ref), ch.headers)
            )
        elif isinstance(ch, EmailChannel):
            notifiers.append(
                EmailNotifier(
                    ch.smtp_host,
                    ch.smtp_port,
                    ch.sender,
                    ch.recipients,
                    starttls=ch.starttls,
                    username=resolve_secret(ch.username_ref),
                    password=resolve_secret(ch.password_ref),
                )
            )
    return notifiers


class AlertDispatcher:
    def __init__(
        self,
        notifiers: Sequence[Notifier],
        min_severity: Severity = Severity.WARNING,
        cooldown: float = 3600,
        metrics: Metrics | None = None,
        clock: Callable[[], float] = time.monotonic,
        attempts: int = 3,
    ) -> None:
        self._notifiers = list(notifiers)
        self._min = _ORDER.index(min_severity)
        self._cooldown = cooldown
        self._metrics = metrics
        self._clock = clock
        self._attempts = attempts
        self._last_sent: dict[tuple[str, str, int | None, str | None], float] = {}

    def select(self, changes: Sequence[Change]) -> list[Change]:
        """Drop low-severity changes and repeats within the cooldown (flapping hosts)."""
        now = self._clock()
        selected = []
        for ch in changes:
            if _ORDER.index(ch.severity) < self._min:
                continue
            key = (ch.kind.value, ch.host, ch.port, ch.after)
            last = self._last_sent.get(key)
            if last is not None and now - last < self._cooldown:
                continue
            self._last_sent[key] = now
            selected.append(ch)
        return selected

    async def dispatch(self, job: str, changes: Sequence[Change]) -> list[Change]:
        selected = self.select(changes)
        if not selected or not self._notifiers:
            return selected

        async def send(n: Notifier) -> None:
            try:
                await retry_async(
                    lambda: n.send(job, selected),
                    attempts=self._attempts,
                    base_delay=1.0,
                    description=f"{n.name} alert",
                )
                outcome = "sent"
            except Exception:
                # Alerting failures must never crash the scan pipeline.
                log.exception("alert channel %s failed", n.name)
                outcome = "failed"
            if self._metrics:
                self._metrics.alerts_total.labels(channel=n.name, result=outcome).inc()

        await asyncio.gather(*(send(n) for n in self._notifiers))
        return selected
