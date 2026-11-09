"""Optional read-only HTTP API (``pip install netmon[api]``).

Bearer-token protected; binds to localhost by default. Put it behind a TLS-terminating
reverse proxy before exposing it beyond the host.
"""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any

from netmon.config import Settings, resolve_secret
from netmon.storage import Storage


def create_app(settings: Settings, storage: Storage) -> Any:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query

    token = resolve_secret(settings.api.token_ref)
    if token is None:
        raise RuntimeError("api.token_ref must be set when the API is enabled")

    def auth(authorization: str = Header(default="")) -> None:
        expected = f"Bearer {token.get_secret_value()}"
        if not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI(title="netmon", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/jobs", dependencies=[Depends(auth)])
    async def jobs() -> list[dict[str, Any]]:
        return [
            {"name": j.name, "profile": j.profile, "interval": j.interval, "enabled": j.enabled}
            for j in settings.jobs
        ]

    @app.get("/v1/hosts", dependencies=[Depends(auth)])
    async def hosts() -> list[dict[str, Any]]:
        return await storage.list_hosts()

    @app.get("/v1/hosts/{address}/history", dependencies=[Depends(auth)])
    async def history(address: str, limit: int = Query(100, le=1000)) -> list[dict[str, Any]]:
        return await storage.host_history(address, limit)

    @app.get("/v1/changes", dependencies=[Depends(auth)])
    async def changes(
        since: datetime | None = None, limit: int = Query(100, le=1000)
    ) -> list[dict[str, Any]]:
        return await storage.list_changes(since, limit)

    @app.get("/v1/scans", dependencies=[Depends(auth)])
    async def scans(job: str | None = None, limit: int = Query(50, le=500)) -> list[dict[str, Any]]:
        return await storage.list_scans(job, limit)

    return app


async def serve_api(settings: Settings, storage: Storage) -> None:
    import uvicorn

    config = uvicorn.Config(
        create_app(settings, storage),
        host=settings.api.host,
        port=settings.api.port,
        log_config=None,
        server_header=False,
    )
    await uvicorn.Server(config).serve()
