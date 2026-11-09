from __future__ import annotations

import pytest

from netmon.retry import retry_async


async def _nosleep(_: float) -> None:
    return None


async def test_retries_then_succeeds() -> None:
    calls = 0

    async def flaky() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise RuntimeError("transient")
        return "ok"

    assert await retry_async(flaky, attempts=3, sleep=_nosleep) == "ok"
    assert calls == 3


async def test_gives_up_and_respects_should_retry() -> None:
    calls = 0

    async def fail() -> None:
        nonlocal calls
        calls += 1
        raise ValueError("permanent")

    with pytest.raises(ValueError):
        await retry_async(fail, attempts=5, sleep=_nosleep, should_retry=lambda e: False)
    assert calls == 1
    with pytest.raises(ValueError):
        await retry_async(fail, attempts=2, sleep=_nosleep)
    assert calls == 3
