"""``netmon`` command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shlex
import signal
import sys
from collections.abc import Sequence
from typing import Any

from netmon import __version__
from netmon.config import ConfigError, Settings, load_settings
from netmon.logging_setup import configure_logging
from netmon.models import ScanStatus
from netmon.policy import PolicyEngine, PolicyViolation
from netmon.runtime import monitor_from_settings
from netmon.scanner import CommandError, build_command
from netmon.scheduler import Scheduler
from netmon.service import ensure_not_root
from netmon.storage import open_storage

log = logging.getLogger("netmon")
DEFAULT_CONFIG = os.environ.get("NETMON_CONFIG", "/etc/netmon/config.yaml")


def _print_json(rows: Any) -> None:
    print(json.dumps(rows, indent=2, default=str))


def cmd_validate(settings: Settings, args: argparse.Namespace) -> int:
    """Validate config, scope and every job's nmap command without scanning."""
    engine = PolicyEngine(settings.policy)
    ok = True
    for job in settings.jobs:
        if args.job and job.name != args.job:
            continue
        try:
            targets = engine.validate_targets(job.targets)
            argv = build_command(
                job,
                settings.nmap,
                settings.policy,
                targets=targets,
                excludes=engine.exclusions(),
                profile="discovery" if job.incremental else None,
            )
            decision = engine.check(job)
            state = "runnable now" if decision.allowed else f"would skip: {decision.reason}"
            print(f"[ok] {job.name} ({state})\n     {shlex.join(argv)}")
        except (PolicyViolation, CommandError) as exc:
            ok = False
            print(f"[FAIL] {job.name}: {exc}", file=sys.stderr)
    return 0 if ok else 1


async def cmd_scan(settings: Settings, args: argparse.Namespace) -> int:
    ensure_not_root(settings)
    jobs = [settings.job(args.job)] if args.job else settings.jobs
    worst = 0
    async with monitor_from_settings(settings) as monitor:
        for job in jobs:
            outcome = await monitor.run_job(job)
            print(f"{job.name}: {outcome.status.value} {outcome.reason}".rstrip())
            for ch in outcome.changes:
                print(f"  [{ch.severity.value}] {ch.message}")
            if outcome.status in (ScanStatus.FAILED, ScanStatus.REFUSED):
                worst = 1
    return worst


async def cmd_run(settings: Settings, args: argparse.Namespace) -> int:
    ensure_not_root(settings)
    async with monitor_from_settings(settings) as monitor:
        if settings.metrics.enabled:
            monitor.metrics.serve(settings.metrics.host, settings.metrics.port)
            m = settings.metrics
            log.info("metrics on http://%s:%d/metrics", m.host, m.port)
        scheduler = Scheduler(monitor, settings.jobs, settings.policy.max_concurrent_scans)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, scheduler.stop)
        api_task = None
        if settings.api.enabled:
            from netmon.api import serve_api

            api_task = asyncio.create_task(serve_api(settings, monitor.storage))
        try:
            await scheduler.run()
        except asyncio.CancelledError:
            pass
        finally:
            if api_task:
                api_task.cancel()
        log.info("scheduler stopped")
    return 0


async def cmd_migrate(settings: Settings, args: argparse.Namespace) -> int:
    storage = open_storage(settings.database)
    try:
        applied = await storage.migrate()
        print(f"applied migrations: {applied}" if applied else "schema up to date")
    finally:
        await storage.close()
    return 0


async def cmd_query(settings: Settings, args: argparse.Namespace) -> int:
    storage = open_storage(settings.database)
    try:
        await storage.migrate()
        if args.command == "hosts":
            _print_json(await storage.list_hosts())
        elif args.command == "changes":
            _print_json(await storage.list_changes(limit=args.limit))
        elif args.command == "scans":
            _print_json(await storage.list_scans(args.job, limit=args.limit))
        elif args.command == "history":
            _print_json(await storage.host_history(args.address, limit=args.limit))
    finally:
        await storage.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netmon", description=__doc__)
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="YAML config path")
    p.add_argument("--version", action="version", version=f"netmon {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("validate", help="validate config and print nmap commands (no scanning)")
    s.add_argument("--job")
    s = sub.add_parser("scan", help="run job(s) once now (still subject to policy)")
    s.add_argument("--job")
    sub.add_parser("run", help="run the scheduler daemon")
    sub.add_parser("migrate", help="apply database migrations")
    for name in ("hosts", "changes", "scans"):
        s = sub.add_parser(name, help=f"list {name} as JSON")
        s.add_argument("--limit", type=int, default=50)
        if name == "scans":
            s.add_argument("--job")
    s = sub.add_parser("history", help="service history for one address")
    s.add_argument("address")
    s.add_argument("--limit", type=int, default=100)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings.logging.level, settings.logging.json_format)
    try:
        if args.command == "validate":
            return cmd_validate(settings, args)
        handler = {
            "scan": cmd_scan,
            "run": cmd_run,
            "migrate": cmd_migrate,
        }.get(args.command, cmd_query)
        return asyncio.run(handler(settings, args))
    except (ConfigError, PermissionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
