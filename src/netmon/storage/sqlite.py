"""SQLite backend (default). Good for a single scanner node; WAL mode, one writer."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

from netmon.models import Change, Host, ScanResult, ScanStatus, Service

T = TypeVar("T")


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _service_from_json(d: dict[str, Any]) -> Service:
    return Service(**{**d, "cpe": tuple(d.get("cpe", ()))})


def split_statements(sql: str) -> list[str]:
    """Split a migration into statements. Strips ``--`` comments first, so migrations
    must not contain ``--`` or ``;`` inside string literals."""
    code = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    return [stmt.strip() for stmt in code.split(";") if stmt.strip()]


def available_migrations() -> list[tuple[int, str]]:
    pkg = resources.files("netmon.storage") / "migrations"
    out = []
    for entry in pkg.iterdir():
        if entry.name.endswith(".sql"):
            out.append((int(entry.name.split("_", 1)[0]), entry.read_text(encoding="utf-8")))
    return sorted(out)


class SQLiteStorage:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.Lock()

    async def _run(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        def locked() -> T:
            with self._lock:
                return fn(self._conn)

        return await asyncio.to_thread(locked)

    # ------------------------------------------------------------------ schema
    async def migrate(self) -> list[int]:
        """Apply pending forward-only migrations; returns the versions applied."""

        def apply(c: sqlite3.Connection) -> list[int]:
            c.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            done = {r[0] for r in c.execute("SELECT version FROM schema_migrations")}
            applied = []
            for version, sql in available_migrations():
                if version in done:
                    continue
                c.execute("BEGIN")
                try:
                    for stmt in split_statements(sql):
                        c.execute(stmt)
                    c.execute(
                        "INSERT INTO schema_migrations VALUES (?, ?)",
                        (version, _iso(datetime.now(UTC))),
                    )
                    c.execute("COMMIT")
                except Exception:
                    c.execute("ROLLBACK")
                    raise
                applied.append(version)
            return applied

        return await self._run(apply)

    # ------------------------------------------------------------------ writes
    async def start_scan(self, job: str, command: list[str], started_at: datetime) -> int:
        def ins(c: sqlite3.Connection) -> int:
            cur = c.execute(
                "INSERT INTO scans (job, status, started_at, command) VALUES (?, ?, ?, ?)",
                (job, ScanStatus.RUNNING.value, _iso(started_at), json.dumps(command)),
            )
            return int(cur.lastrowid or 0)

        return await self._run(ins)

    async def fail_scan(
        self, scan_id: int, status: ScanStatus, error: str, finished_at: datetime
    ) -> None:
        await self._run(
            lambda c: c.execute(
                "UPDATE scans SET status=?, error=?, finished_at=? WHERE id=?",
                (status.value, error[:4000], _iso(finished_at), scan_id),
            )
        )

    async def complete_scan(
        self,
        scan_id: int,
        result: ScanResult,
        state: Mapping[str, Host],
        port_scanned: Iterable[str],
        changes: Iterable[Change],
    ) -> None:
        port_scanned = set(port_scanned)
        changes = list(changes)
        now = _iso(result.finished_at)

        def tx(c: sqlite3.Connection) -> None:
            c.execute("BEGIN")
            try:
                c.execute(
                    "UPDATE scans SET status=?, finished_at=?, nmap_version=?, hosts_up=?, "
                    "summary=?, command=? WHERE id=?",
                    (
                        ScanStatus.SUCCEEDED.value,
                        now,
                        result.nmap_version,
                        len(result.up_hosts()),
                        result.summary,
                        json.dumps(result.commands),
                        scan_id,
                    ),
                )
                for h in result.hosts:
                    c.execute(
                        "INSERT INTO observations VALUES (?, ?, ?)", (scan_id, h.address, h.status)
                    )
                    c.executemany(
                        "INSERT INTO services VALUES (?,?,?,?,?,?,?,?,?,?)",
                        [
                            (
                                scan_id,
                                h.address,
                                s.port,
                                s.protocol,
                                s.state,
                                s.name,
                                s.product,
                                s.version,
                                s.extra_info,
                                json.dumps(list(s.cpe)),
                            )
                            for s in h.services
                        ],
                    )
                    if h.status == "up":
                        c.execute(
                            "INSERT INTO hosts (address, first_seen, last_seen, hostnames, mac, "
                            "vendor, os_guess) VALUES (?,?,?,?,?,?,?) "
                            "ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen, "
                            "hostnames=excluded.hostnames, "
                            "mac=COALESCE(excluded.mac, hosts.mac), "
                            "vendor=COALESCE(excluded.vendor, hosts.vendor), "
                            "os_guess=COALESCE(excluded.os_guess, hosts.os_guess)",
                            (
                                h.address,
                                now,
                                now,
                                json.dumps(h.hostnames),
                                h.mac,
                                h.vendor,
                                h.os_guess,
                            ),
                        )
                # Replace the job's current state snapshot.
                previous_scans = {
                    r["address"]: r["last_port_scan"]
                    for r in c.execute(
                        "SELECT address, last_port_scan FROM host_state WHERE job=?", (result.job,)
                    )
                }
                c.execute("DELETE FROM host_state WHERE job=?", (result.job,))
                for addr, h in state.items():
                    c.execute(
                        "INSERT INTO host_state VALUES (?,?,?,?,?,?)",
                        (
                            result.job,
                            addr,
                            h.status,
                            json.dumps([asdict(s) for s in h.services]),
                            now,
                            now if addr in port_scanned else previous_scans.get(addr),
                        ),
                    )
                c.executemany(
                    "INSERT INTO changes (scan_id, job, detected_at, kind, severity, host, port, "
                    "protocol, before, after, message) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            scan_id,
                            result.job,
                            now,
                            ch.kind.value,
                            ch.severity.value,
                            ch.host,
                            ch.port,
                            ch.protocol,
                            ch.before,
                            ch.after,
                            ch.message,
                        )
                        for ch in changes
                    ],
                )
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise

        await self._run(tx)

    # ------------------------------------------------------------------ reads
    async def load_state(self, job: str) -> dict[str, Host]:
        def q(c: sqlite3.Connection) -> dict[str, Host]:
            rows = c.execute(
                "SELECT address, status, services FROM host_state WHERE job=?", (job,)
            ).fetchall()
            return {
                r["address"]: Host(
                    address=r["address"],
                    status=r["status"],
                    services=[_service_from_json(s) for s in json.loads(r["services"])],
                )
                for r in rows
            }

        return await self._run(q)

    async def last_port_scans(self, job: str) -> dict[str, datetime]:
        def q(c: sqlite3.Connection) -> dict[str, datetime]:
            rows = c.execute(
                "SELECT address, last_port_scan FROM host_state "
                "WHERE job=? AND last_port_scan IS NOT NULL",
                (job,),
            )
            return {r[0]: datetime.fromisoformat(r[1]) for r in rows}

        return await self._run(q)

    async def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return await self._run(lambda c: [dict(r) for r in c.execute(sql, params)])

    async def list_hosts(self) -> list[dict[str, Any]]:
        return await self._rows("SELECT * FROM hosts ORDER BY address")

    async def list_changes(
        self, since: datetime | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return await self._rows(
            "SELECT * FROM changes WHERE detected_at >= ? ORDER BY id DESC LIMIT ?",
            (_iso(since) if since else "", limit),
        )

    async def list_scans(self, job: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        if job:
            return await self._rows(
                "SELECT * FROM scans WHERE job=? ORDER BY id DESC LIMIT ?", (job, limit)
            )
        return await self._rows("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    async def host_history(self, address: str, limit: int = 50) -> list[dict[str, Any]]:
        return await self._rows(
            "SELECT s.started_at, s.job, sv.port, sv.protocol, sv.state, sv.name, sv.product, "
            "sv.version FROM services sv JOIN scans s ON s.id = sv.scan_id "
            "WHERE sv.address=? ORDER BY s.id DESC, sv.port LIMIT ?",
            (address, limit),
        )

    async def close(self) -> None:
        await self._run(lambda c: c.close())
