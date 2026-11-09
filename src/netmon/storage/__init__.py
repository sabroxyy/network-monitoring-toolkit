"""Persistence of scans, inventory, per-job state and detected changes."""

from netmon.storage.base import Storage, open_storage

__all__ = ["Storage", "open_storage"]
