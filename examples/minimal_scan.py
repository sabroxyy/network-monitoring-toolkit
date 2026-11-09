#!/usr/bin/env python3
"""Minimal end-to-end example: scan loopback twice and print detected changes.

    python examples/minimal_scan.py            # scans 127.0.0.1 ports 22,80,8000-8100

Start something in between runs (e.g. `python -m http.server 8000`) to see a
PORT_OPENED change. Uses only an unprivileged TCP connect scan of your own machine.
"""

from __future__ import annotations

import asyncio

from netmon.config import Settings
from netmon.metrics import Metrics
from netmon.runtime import monitor_from_settings

SETTINGS = Settings.model_validate(
    {
        "database": "sqlite:///netmon-example.db",
        "allow_root": True,  # example only; never in production
        "policy": {
            "allowed_networks": ["127.0.0.0/8"],
            "authorization": {"owner": "me", "reference": "local-demo"},
        },
        "jobs": [
            {
                "name": "loopback",
                "targets": ["127.0.0.1"],
                "profile": "services",
                "ports": "22,80,8000-8100",
                "timing": 4,
            }
        ],
        "logging": {"json": False},
    }
)


async def main() -> None:
    async with monitor_from_settings(SETTINGS, metrics=Metrics()) as monitor:
        job = SETTINGS.job("loopback")
        outcome = await monitor.run_job(job)
        print(f"run 1: {outcome.status.value} {outcome.reason}")
        state = await monitor.storage.load_state("loopback")
        for addr, host in state.items():
            for svc in host.open_services().values():
                print(f"  {addr} {svc.port}/{svc.protocol} {svc.fingerprint}")

        await asyncio.to_thread(
            input, "Start/stop a service on 127.0.0.1:8000-8100, then press Enter... "
        )
        outcome = await monitor.run_job(job)
        print(f"run 2: {outcome.status.value}")
        for change in outcome.changes:
            print(f"  [{change.severity.value}] {change.message}")
        if not outcome.changes:
            print("  no changes")


if __name__ == "__main__":
    asyncio.run(main())
