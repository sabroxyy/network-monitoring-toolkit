from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, Protocol

from netmon.models import Change, Host, ScanResult, ScanStatus


class Storage(Protocol):
    """Backend-agnostic storage contract. All methods are async-safe."""

    async def migrate(self) -> list[int]: ...
    async def start_scan(self, job: str, command: list[str], started_at: datetime) -> int: ...
    async def complete_scan(
        self,
        scan_id: int,
        result: ScanResult,
        state: Mapping[str, Host],
        port_scanned: Iterable[str],
        changes: Iterable[Change],
    ) -> None: ...
    async def fail_scan(
        self, scan_id: int, status: ScanStatus, error: str, finished_at: datetime
    ) -> None: ...
    async def load_state(self, job: str) -> dict[str, Host]: ...
    async def last_port_scans(self, job: str) -> dict[str, datetime]: ...
    async def list_hosts(self) -> list[dict[str, Any]]: ...
    async def list_changes(
        self, since: datetime | None = None, limit: int = 100
    ) -> list[dict[str, Any]]: ...
    async def list_scans(self, job: str | None = None, limit: int = 50) -> list[dict[str, Any]]: ...
    async def host_history(self, address: str, limit: int = 50) -> list[dict[str, Any]]: ...
    async def close(self) -> None: ...


def open_storage(url: str) -> Storage:
    """Create a storage backend from a URL such as ``sqlite:///var/lib/netmon/netmon.db``."""
    if url.startswith("sqlite://"):
        from netmon.storage.sqlite import SQLiteStorage

        return SQLiteStorage(_sqlite_path(url))
    if url.startswith(("postgres://", "postgresql://")):
        raise NotImplementedError(
            "PostgreSQL backend is an extension point: implement Storage in "
            "netmon/storage/postgres.py (see docs/architecture.md#storage)"
        )
    raise ValueError(f"unsupported database URL: {url!r}")


def _sqlite_path(url: str) -> str:
    # sqlite:///relative.db -> "relative.db"; sqlite:////abs/path.db -> "/abs/path.db";
    # sqlite:///:memory: -> ":memory:"
    if not url.startswith("sqlite:///"):
        raise ValueError("SQLite URLs must look like sqlite:///path/to/netmon.db")
    return url.removeprefix("sqlite:///")
