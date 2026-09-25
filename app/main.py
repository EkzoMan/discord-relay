"""FastAPI application: dashboard UI + admin API + relay bot lifespan."""

from __future__ import annotations

import asyncio
import logging
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from .models import RelayMapping, RelayMappingCreate
from .relay_bot import RelayClient, run_relay_bot
from .settings import Settings, get_settings
from .store import ConfigStore, DuplicateChannelError
from .webhooks import send_to_webhook

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# auto_error=False: enforcement depends on settings (see require_auth).
basic_credentials = HTTPBasic(auto_error=False)


async def require_auth(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(basic_credentials),
) -> str | None:
    """Protect every UI/API route with HTTP Basic when credentials are set.

    Uses constant-time comparisons. Returns the authenticated username, or
    ``None`` when auth is disabled entirely.
    """
    settings: Settings = request.app.state.settings
    if not settings.ui_auth_enabled:
        return None
    if (
        credentials is not None
        and settings.ui_username is not None
        and settings.ui_password is not None
        and secrets.compare_digest(credentials.username, settings.ui_username)
        and secrets.compare_digest(credentials.password, settings.ui_password)
    ):
        return credentials.username
    raise HTTPException(
        status_code=401,
        detail="Authentication required.",
        headers={"WWW-Authenticate": 'Basic realm="Discord Relay", charset="UTF-8"'},
    )


def mask_webhook_url(url: str) -> str:
    """Return a display-safe webhook URL.

    Keeps scheme/host and the channel-id path, but shows only the first 8
    characters of the secret token: ``https://discord.com/api/webhooks/<channel>/<abcd1234>…``
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url[:40] + "…"
    segments = [s for s in parsed.path.split("/") if s]
    if not segments:
        return f"{parsed.scheme}://{parsed.netloc}"
    token = segments[-1]
    masked_token = f"{token[:8]}…" if len(token) > 8 else "…"
    path = "/" + "/".join(segments[:-1] + [masked_token])
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _redirect_with(kind: str, message: str) -> RedirectResponse:
    """303 redirect back to the dashboard carrying a one-line flash message."""
    query = urlencode({"flash": message, "kind": kind})
    return RedirectResponse(url=f"/?{query}", status_code=303)


def _validation_message(exc: ValidationError) -> str:
    details = []
    for err in exc.errors():
        field = ".".join(str(part) for part in err["loc"]) or "value"
        details.append(f"{field}: {err['msg']}")
    return "Invalid mapping — " + "; ".join(details)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as http:
        app.state.http = http

        task: asyncio.Task | None = None
        if settings.discord_bot_token:
            client = RelayClient(app.state.store, settings)
            app.state.relay_client = client
            task = asyncio.create_task(
                run_relay_bot(app.state.store, settings, client=client),
                name="relay-bot",
            )
            app.state.relay_task = task
            logger.info("Relay bot task started.")
        else:
            logger.warning(
                "DISCORD_BOT_TOKEN is not set — running web UI only; nothing will be relayed."
            )

        try:
            yield
        finally:
            # Graceful shutdown: ask the gateway to close first so
            # run_relay_bot() returns normally, then cancel as a safety net.
            client = getattr(app.state, "relay_client", None)
            if client is not None and not client.is_closed():
                try:
                    await client.close()
                except Exception:
                    logger.exception("Error while closing the Discord client.")
            if task is not None:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception:
                    logger.exception("Relay bot task terminated with an error.")


def create_app(
    settings: Settings | None = None,
    store: ConfigStore | None = None,
) -> FastAPI:
    """Application factory (used by uvicorn and by the tests)."""
    settings = settings or get_settings()
    if store is None:
        store = ConfigStore(settings.relay_config_path)
        store.load()

    app = FastAPI(title="Discord Relay", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.relay_client = None
    app.state.relay_task = None

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
    async def dashboard(request: Request) -> HTMLResponse:
        app_settings: Settings = request.app.state.settings
        store: ConfigStore = request.app.state.store
        client: RelayClient | None = getattr(request.app.state, "relay_client", None)
        mappings = [
            {
                "id": m.id,
                "name": m.name,
                "source_channel_id": m.source_channel_id,
                "masked_url": mask_webhook_url(m.target_webhook_url),
            }
            for m in store.list_mappings()
        ]
        context = {
            "request": request,
            "mappings": mappings,
            "mapping_count": len(mappings),
            "bot_enabled": bool(app_settings.discord_bot_token),
            "bot_running": bool(client is not None and client.is_ready()),
            "config_path": app_settings.relay_config_path,
            "flash": request.query_params.get("flash"),
            "flash_kind": request.query_params.get("kind", "ok"),
        }
        return templates.TemplateResponse(request, "index.html", context)

    @app.get("/health", dependencies=[Depends(require_auth)])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/status", dependencies=[Depends(require_auth)])
    async def status(request: Request) -> dict[str, object]:
        app_settings: Settings = request.app.state.settings
        client: RelayClient | None = getattr(request.app.state, "relay_client", None)
        return {
            "bot_enabled": bool(app_settings.discord_bot_token),
            "bot_running": bool(client is not None and client.is_ready()),
            "mappings": len(request.app.state.store.list_mappings()),
            "config_path": app_settings.relay_config_path,
        }

    @app.post("/mappings", dependencies=[Depends(require_auth)])
    async def create_mapping(request: Request) -> RedirectResponse:
        store: ConfigStore = request.app.state.store
        form = await request.form()
        try:
            payload = RelayMappingCreate(
                name=str(form.get("name") or ""),
                source_channel_id=form.get("source_channel_id"),
                target_webhook_url=str(form.get("target_webhook_url") or ""),
            )
        except ValidationError as exc:
            return _redirect_with("error", _validation_message(exc))

        mapping = RelayMapping(**payload.model_dump())
        try:
            store.add(mapping)
        except DuplicateChannelError as exc:
            return _redirect_with("error", str(exc))
        except OSError:
            logger.exception("Could not persist the config file.")
            return _redirect_with("error", "Could not save the configuration file.")

        label = mapping.name or mapping.id[:8]
        return _redirect_with(
            "ok", f"Added mapping “{label}” for channel {mapping.source_channel_id}."
        )

    @app.post("/mappings/{mapping_id}/delete", dependencies=[Depends(require_auth)])
    async def delete_mapping(mapping_id: str, request: Request) -> RedirectResponse:
        store: ConfigStore = request.app.state.store
        removed = store.remove(mapping_id)
        if removed is None:
            return _redirect_with("error", "Mapping not found (it may have been deleted already).")
        return _redirect_with(
            "ok", f"Deleted mapping for channel {removed.source_channel_id}."
        )

    @app.post("/mappings/{mapping_id}/test", dependencies=[Depends(require_auth)])
    async def test_mapping(mapping_id: str, request: Request) -> RedirectResponse:
        store: ConfigStore = request.app.state.store
        mapping = store.get(mapping_id)
        if mapping is None:
            return _redirect_with("error", "Mapping not found.")
        label = mapping.name or f"channel {mapping.source_channel_id}"
        ok = await send_to_webhook(
            mapping.target_webhook_url,
            username=f"Relay test — {label}"[:80],
            avatar_url=None,
            content=(
                "\U0001F514 Test message from Discord Relay. "
                "If you can see this, the mapping works."
            ),
            http_client=request.app.state.http,
        )
        if ok:
            return _redirect_with("ok", f"Test message sent for “{label}”.")
        # Never echo the webhook URL; details are in the server log only.
        return _redirect_with("error", f"Test send failed for “{label}” — see server logs.")

    return app


app = create_app()


if __name__ == "__main__":
    # Convenience for local development: `python -m app.main`
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=get_settings().port)
