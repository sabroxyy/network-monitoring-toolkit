"""Wiring: build the object graph from Settings (used by the CLI, API and examples)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from netmon.alerting import AlertDispatcher, build_notifiers
from netmon.config import Settings
from netmon.metrics import Metrics
from netmon.scanner import NmapRunner, Runner
from netmon.service import Monitor
from netmon.storage import open_storage


@asynccontextmanager
async def monitor_from_settings(
    settings: Settings, runner: Runner | None = None, metrics: Metrics | None = None
) -> AsyncIterator[Monitor]:
    storage = open_storage(settings.database)
    await storage.migrate()
    metrics = metrics or Metrics()
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
        dispatcher = AlertDispatcher(
            build_notifiers(settings.alerting, client),
            min_severity=settings.alerting.min_severity,
            cooldown=settings.alerting.cooldown,
            metrics=metrics,
        )
        try:
            yield Monitor(settings, storage, runner or NmapRunner(), dispatcher, metrics)
        finally:
            await storage.close()
