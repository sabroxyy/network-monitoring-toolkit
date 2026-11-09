"""Async retry with exponential backoff and full jitter."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 2.0,
    max_delay: float = 120.0,
    should_retry: Callable[[BaseException], bool] = lambda exc: True,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    description: str = "operation",
) -> T:
    """Call ``fn`` up to ``attempts`` times. Delay ~ U(0, min(max, base * 2**n))."""
    for attempt in range(1, attempts + 1):
        try:
            return await fn()
        except Exception as exc:
            if attempt >= attempts or not should_retry(exc):
                raise
            delay = random.uniform(0, min(max_delay, base_delay * 2 ** (attempt - 1)))  # noqa: S311
            log.warning(
                "%s failed (attempt %d/%d): %s; retrying in %.1fs",
                description,
                attempt,
                attempts,
                exc,
                delay,
            )
            await sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
