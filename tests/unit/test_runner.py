from __future__ import annotations

import pytest

from netmon.scanner import NmapFailed, NmapNotFound, NmapRunner, NmapTimeout


async def test_success_returns_stdout() -> None:
    assert (await NmapRunner().run(["echo", "<nmaprun/>"], timeout=5)).strip() == "<nmaprun/>"


async def test_timeout_kills_process() -> None:
    with pytest.raises(NmapTimeout):
        await NmapRunner().run(["sleep", "10"], timeout=0.2)


async def test_nonzero_exit() -> None:
    with pytest.raises(NmapFailed) as exc:
        await NmapRunner().run(["false"], timeout=5)
    assert exc.value.returncode == 1 and exc.value.transient


async def test_missing_binary_is_permanent() -> None:
    with pytest.raises(NmapNotFound) as exc:
        await NmapRunner().run(["definitely-not-nmap-xyz"], timeout=5)
    assert not exc.value.transient


async def test_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETMON_SECRET_TOKEN", "leak-me")
    out = await NmapRunner().run(["env"], timeout=5)
    assert "leak-me" not in out and "PATH=" in out
