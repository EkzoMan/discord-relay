"""FastAPI application: multi-user dashboard (session auth) + relay bot lifespan.

Auth model
----------
- Login happens at ``POST /login``; a random session token is issued, only its
  SHA-256 digest is stored, and the raw value travels in an ``HttpOnly`` cookie.
- Page routes guard with :func:`require_user_page` (redirect to ``/login``);
  JSON/API routes guard with :func:`require_api_user` (HTTP 401).
- Ownership: users only see/manage their own relays; admins additionally get
  an "all relays" view and user management. Access checks live in the store
  (``get_mapping_for_user`` / ``remove_mapping_for_user``) so the bot's
  unauthenticated hot path stays separate from UI permission logic.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from .auth import MAX_PASSWORD_LENGTH, password_is_too_long
from .models import (
    ROLES,
    RelayMapping,
    RelayMappingCreate,
    RelayMappingView,
    User,
    UserPublic,
)
from .ratelimit import LoginRateLimiter, normalize_login_key
from .relay_bot import RelayClient, run_relay_bot
from .settings import Settings, get_settings
from .store import (
    DuplicateChannelError,
    DuplicateUsernameError,
    RelayStore,
)
from .webhooks import send_to_webhook

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

#: Minimum accepted password length for admin-created accounts / self-service
#: changes. (Bootstrap/legacy accounts are exempt — they come from env vars.)
MIN_PASSWORD_LENGTH = 8

#: Generic lockout message: no hints about which account exists, remaining
#: attempt counts or unlock times.
TOO_MANY_LOGINS_MESSAGE = "Too many login attempts. Try again later."

_UNSET = object()


class LoginRequired(Exception):
    """Raised by page guards when there is no valid session cookie.

    Converted into a 302 -> /login by the exception handler registered in
    :func:`create_app` (raising from a dependency cannot return a redirect
    directly).
    """


# --------------------------------------------------------------------------- #
# Session/auth helpers
# --------------------------------------------------------------------------- #

def _request_is_https(request: Request) -> bool:
    """Best-effort "are we behind TLS" check (honours one proxy hop)."""
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _client_ip(request: Request) -> str:
    """Client IP for the login rate limiter (honours one proxy hop).

    Mirrors :func:`_request_is_https`: behind the documented reverse-proxy
    setup the real client is the first ``X-Forwarded-For`` entry. Direct
    exposure (no proxy) means this header is attacker-controlled — the
    README explicitly requires a reverse proxy for anything public, and a
    spoofed header only lets a caller pick their own throttle bucket, which
    is no worse than the pre-limiter behaviour.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip() or "unknown"
    return request.client.host if request.client is not None else "unknown"


def _cookie_secure(settings: Settings, request: Request) -> bool:
    """Resolve SESSION_COOKIE_SECURE (auto/true/false) for this request."""
    mode = getattr(settings, "session_cookie_secure", "auto")
    if mode == "true":
        return True
    if mode == "false":
        return False
    return _request_is_https(request)


def get_current_user(request: Request) -> User | None:
    """Resolve the session cookie to a live, active user (cached per request)."""
    cached = getattr(request.state, "current_user", _UNSET)
    if cached is not _UNSET:
        return cached  # type: ignore[return-value]
    settings: Settings = request.app.state.settings
    store: RelayStore = request.app.state.store
    token = request.cookies.get(settings.session_cookie_name)
    user = store.get_user_by_token(token) if token else None
    request.state.current_user = user
    return user


def require_user_page(request: Request) -> User:
    """Guard for HTML routes: redirect browsers to the login page."""
    user = get_current_user(request)
    if user is None:
        raise LoginRequired()
    return user


def require_api_user(request: Request) -> User:
    """Guard for JSON/API routes: plain 401 (no redirect for non-browsers)."""
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_admin(user: User = Depends(require_user_page)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


def _set_session_cookie(response: Response, request: Request, raw_token: str) -> None:
    settings: Settings = request.app.state.settings
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(settings, request),
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    settings: Settings = request.app.state.settings
    response.delete_cookie(key=settings.session_cookie_name, path="/")


# --------------------------------------------------------------------------- #
# Small display helpers
# --------------------------------------------------------------------------- #

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


def _redirect_with(message: str, kind: str = "ok", base: str = "/") -> RedirectResponse:
    """303 redirect back to *base* carrying a one-line flash message."""
    query = urlencode({"flash": message, "kind": kind})
    sep = "&" if "?" in base else "?"
    return RedirectResponse(url=f"{base}{sep}{query}", status_code=303)


def _validation_message(exc: ValidationError) -> str:
    details = []
    for err in exc.errors():
        field = ".".join(str(part) for part in err["loc"]) or "value"
        details.append(f"{field}: {err['msg']}")
    return "Invalid mapping — " + "; ".join(details)


def _mapping_rows(
    mappings: list[RelayMapping],
    owner_names: dict[str, str],
) -> list[RelayMappingView]:
    """Template-safe view objects: the full webhook URL is replaced by a
    masked one, and ownership (with username) is attached for the admin view."""
    return [
        RelayMappingView(
            id=m.id,
            name=m.name,
            source_channel_id=m.source_channel_id,
            owner_user_id=m.owner_user_id,
            owner_username=owner_names.get(m.owner_user_id, m.owner_user_id[:8]),
            masked_url=mask_webhook_url(m.target_webhook_url),
            created_at=m.created_at,
        )
        for m in mappings
    ]


# --------------------------------------------------------------------------- #
# Lifespan
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    store: RelayStore = app.state.store
    # Small SQLite ops, but keep the event loop clean anyway.
    await run_in_threadpool(store.initialize)
    await run_in_threadpool(
        store.bootstrap_admin, settings.admin_username, settings.admin_password
    )
    imported = await run_in_threadpool(store.import_legacy_json, settings.relay_config_path)
    if imported:
        logger.info("Legacy JSON migration imported %d mapping(s).", imported)
    await run_in_threadpool(store.purge_expired_sessions)

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as http:
        app.state.http = http

        task: asyncio.Task | None = None
        if settings.discord_bot_token:
            client = RelayClient(store, settings)
            app.state.relay_client = client
            task = asyncio.create_task(
                run_relay_bot(store, settings, client=client),
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


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #

def create_app(
    settings: Settings | None = None,
    store: RelayStore | None = None,
    login_limiter: LoginRateLimiter | None = None,
) -> FastAPI:
    """Application factory (used by uvicorn and by the tests).

    ``login_limiter`` exists so tests (and, later, a shared-store deployment)
    can inject a limiter with a controllable clock; production wiring derives
    one from the settings below.
    """
    settings = settings or get_settings()
    if store is None:
        store = RelayStore(settings.relay_db_path)
    if login_limiter is None:
        login_limiter = LoginRateLimiter(
            max_attempts=settings.login_max_attempts,
            window_seconds=settings.login_lockout_minutes * 60,
        )

    app = FastAPI(title="Discord Relay", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.login_limiter = login_limiter
    app.state.relay_client = None
    app.state.relay_task = None

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired) -> RedirectResponse:
        return RedirectResponse(url="/login", status_code=302)

    # ------------------------------------------------------------------ #
    # Public routes
    # ------------------------------------------------------------------ #

    @app.get("/health")
    async def health() -> dict[str, str]:
        # Public liveness probe: deliberately exposes nothing beyond "ok".
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        if get_current_user(request) is not None:
            return RedirectResponse(url="/", status_code=302)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "user": None,
                "error": None,
                "flash": request.query_params.get("flash"),
                "flash_kind": request.query_params.get("kind", "ok"),
            },
        )

    @app.post("/login")
    async def login_submit(request: Request) -> Response:
        store: RelayStore = request.app.state.store
        settings: Settings = request.app.state.settings
        limiter: LoginRateLimiter = request.app.state.login_limiter
        form = await request.form()
        username = str(form.get("username") or "")
        password = str(form.get("password") or "")
        key = normalize_login_key(username, _client_ip(request))

        def _denied(message: str, status: int) -> Response:
            """Render the login form with a generic error.

            The username and password are deliberately never logged here:
            failed-attempt telemetry belongs to the limiter, and the only
            client-visible strings are the fixed messages below.
            """
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "request": request,
                    "user": None,
                    "error": message,
                    "flash": None,
                    "flash_kind": "ok",
                },
                status_code=status,
            )

        # Locked out? Do not even pay the PBKDF2 cost — the answer is "no"
        # for the whole window regardless of the credentials.
        if limiter.is_locked(key):
            logger.warning("Throttled login from ip=%s", _client_ip(request))
            return _denied(TOO_MANY_LOGINS_MESSAGE, 429)

        # Oversized passwords cannot match any stored hash (creation rejects
        # them) and would inflate the hashing cost; fail the same generic way
        # while still counting the attempt.
        if password_is_too_long(password):
            if limiter.register_failure(key):
                return _denied(TOO_MANY_LOGINS_MESSAGE, 429)
            return _denied("Неверный логин или пароль.", 401)

        user = await run_in_threadpool(store.authenticate, username, password)
        if user is None:
            # One generic message for unknown user / wrong password /
            # disabled account: never reveal which part was wrong.
            # The attempted username/password are never logged.
            if limiter.register_failure(key):
                logger.warning("Throttled login from ip=%s", _client_ip(request))
                return _denied(TOO_MANY_LOGINS_MESSAGE, 429)
            return _denied("Неверный логин или пароль.", 401)

        limiter.register_success(key)
        raw_token = await run_in_threadpool(
            store.create_session, user.id, settings.session_ttl_hours
        )
        redirect = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(redirect, request, raw_token)
        logger.info("User %s logged in.", user.username)
        return redirect

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        store: RelayStore = request.app.state.store
        settings: Settings = request.app.state.settings
        token = request.cookies.get(settings.session_cookie_name)
        if token:
            await run_in_threadpool(store.delete_session, token)
        redirect = _redirect_with("Вы вышли из системы.", "ok", base="/login")
        _clear_session_cookie(redirect, request)
        return redirect

    # ------------------------------------------------------------------ #
    # Authenticated routes (any role)
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, user: User = Depends(require_user_page)) -> HTMLResponse:
        store: RelayStore = request.app.state.store
        settings: Settings = request.app.state.settings
        client: RelayClient | None = getattr(request.app.state, "relay_client", None)

        mine = await run_in_threadpool(store.list_mappings, user.id)
        all_rows: list[RelayMappingView] = []
        total = len(mine)
        if user.role == "admin":
            pairs = await run_in_threadpool(store.list_all_with_owner)
            owner_names = {m.owner_user_id: name or "?" for m, name in pairs}
            all_rows = _mapping_rows([m for m, _ in pairs], owner_names)
            total = len(all_rows)
        else:
            owner_names = {user.id: user.username}

        context = {
            "request": request,
            "user": user,
            "mappings": _mapping_rows(mine, owner_names),
            "all_mappings": all_rows,
            "mapping_count": len(mine),
            "total_count": total,
            "bot_enabled": bool(settings.discord_bot_token),
            "bot_running": bool(client is not None and client.is_ready()),
            "flash": request.query_params.get("flash"),
            "flash_kind": request.query_params.get("kind", "ok"),
        }
        return templates.TemplateResponse(request, "index.html", context)

    @app.get("/status")
    async def status(
        request: Request, user: User = Depends(require_api_user)
    ) -> dict[str, object]:
        """Authenticated JSON summary. Never contains webhook URLs or hashes."""
        settings: Settings = request.app.state.settings
        store: RelayStore = request.app.state.store
        client: RelayClient | None = getattr(request.app.state, "relay_client", None)
        visible = await run_in_threadpool(
            store.count_mappings, None if user.role == "admin" else user.id
        )
        return {
            "user": {"username": user.username, "role": user.role},
            "bot_enabled": bool(settings.discord_bot_token),
            "bot_running": bool(client is not None and client.is_ready()),
            "mappings": visible,
        }

    @app.post("/mappings")
    async def create_mapping(
        request: Request, user: User = Depends(require_user_page)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        form = await request.form()
        try:
            payload = RelayMappingCreate(
                name=str(form.get("name") or ""),
                source_channel_id=form.get("source_channel_id"),
                target_webhook_url=str(form.get("target_webhook_url") or ""),
            )
        except ValidationError as exc:
            return _redirect_with(_validation_message(exc), "error")

        # Ownership comes from the session only — a spoofed owner field in the
        # form is structurally impossible to honour.
        mapping = RelayMapping(**payload.model_dump(), owner_user_id=user.id)
        try:
            await run_in_threadpool(store.add_mapping, mapping)
        except DuplicateChannelError as exc:
            return _redirect_with(str(exc), "error")
        except ValueError:
            return _redirect_with("Could not save the mapping.", "error")

        label = mapping.name or mapping.id[:8]
        return _redirect_with(
            f"Added mapping “{label}” for channel {mapping.source_channel_id}."
        )

    @app.post("/mappings/{mapping_id}/delete")
    async def delete_mapping(
        mapping_id: str, request: Request, user: User = Depends(require_user_page)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        # Same message whether the row is missing or owned by someone else:
        # unauthorized probes learn nothing about other users' data.
        removed = await run_in_threadpool(store.remove_mapping_for_user, mapping_id, user)
        if removed is None:
            return _redirect_with("Mapping not found (or you have no access to it).", "error")
        return _redirect_with(
            f"Deleted mapping for channel {removed.source_channel_id}."
        )

    @app.post("/mappings/{mapping_id}/test")
    async def test_mapping(
        mapping_id: str, request: Request, user: User = Depends(require_user_page)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        mapping = await run_in_threadpool(store.get_mapping_for_user, mapping_id, user)
        if mapping is None:
            return _redirect_with("Mapping not found (or you have no access to it).", "error")
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
            return _redirect_with(f"Test message sent for “{label}”.")
        # Never echo the webhook URL; details are in the server log only.
        return _redirect_with(f"Test send failed for “{label}” — see server logs.")

    # ------------------------------------------------------------------ #
    # Self-service password change
    # ------------------------------------------------------------------ #

    @app.get("/account/password", response_class=HTMLResponse)
    async def change_password_page(
        request: Request, user: User = Depends(require_user_page)
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "change_password.html",
            {
                "request": request,
                "user": user,
                "flash": request.query_params.get("flash"),
                "flash_kind": request.query_params.get("kind", "ok"),
            },
        )

    @app.post("/account/password")
    async def change_password(
        request: Request, user: User = Depends(require_user_page)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        settings: Settings = request.app.state.settings
        base = "/account/password"
        form = await request.form()
        current = str(form.get("current_password") or "")
        new = str(form.get("new_password") or "")
        confirm = str(form.get("confirm_password") or "")

        if not await run_in_threadpool(store.verify_user_password, user.id, current):
            return _redirect_with("Текущий пароль неверен.", "error", base=base)
        if len(new) < MIN_PASSWORD_LENGTH:
            return _redirect_with(
                f"Новый пароль должен быть не короче {MIN_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        if password_is_too_long(new):
            return _redirect_with(
                f"Новый пароль должен быть не длиннее {MAX_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        if new != confirm:
            return _redirect_with("Новые пароли не совпадают.", "error", base=base)

        await run_in_threadpool(store.set_password, user.id, new)
        # Log out every *other* session; the current cookie stays valid.
        current_token = request.cookies.get(settings.session_cookie_name, "")
        await run_in_threadpool(
            store.delete_sessions_for_user, user.id, current_token or None
        )
        logger.info("User %s changed their password; other sessions revoked.", user.username)
        return _redirect_with("Пароль обновлён. Остальные сессии завершены.", "ok", base=base)

    # ------------------------------------------------------------------ #
    # Admin routes
    # ------------------------------------------------------------------ #

    @app.get("/admin/users", response_class=HTMLResponse)
    async def admin_users(
        request: Request, admin: User = Depends(require_admin)
    ) -> HTMLResponse:
        store: RelayStore = request.app.state.store
        users = await run_in_threadpool(store.list_users)
        return templates.TemplateResponse(
            request,
            "admin_users.html",
            {
                "request": request,
                "user": admin,
                # UserPublic: password_hash is structurally absent from what
                # the template can see.
                "users": [UserPublic.from_user(u) for u in users],
                "flash": request.query_params.get("flash"),
                "flash_kind": request.query_params.get("kind", "ok"),
            },
        )

    @app.post("/admin/users")
    async def admin_create_user(
        request: Request, admin: User = Depends(require_admin)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        base = "/admin/users"
        form = await request.form()
        username = str(form.get("username") or "").strip()
        password = str(form.get("password") or "")
        role = str(form.get("role") or "user")

        if not username or len(username) > 32:
            return _redirect_with("Логин должен быть 1–32 символа.", "error", base=base)
        if role not in ROLES:
            return _redirect_with("Роль должна быть 'user' или 'admin'.", "error", base=base)
        if len(password) < MIN_PASSWORD_LENGTH:
            return _redirect_with(
                f"Пароль должен быть не короче {MIN_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        if password_is_too_long(password):
            # Bound PBKDF2 cost at the input boundary (see app/auth.py).
            return _redirect_with(
                f"Пароль должен быть не длиннее {MAX_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        try:
            await run_in_threadpool(store.create_user, username, password, role)
        except DuplicateUsernameError:
            return _redirect_with(
                f"Пользователь “{username}” уже существует.", "error", base=base
            )
        except ValueError as exc:
            return _redirect_with(str(exc), "error", base=base)
        return _redirect_with(f"Пользователь “{username}” создан.", "ok", base=base)

    @app.post("/admin/users/{user_id}/reset-password")
    async def admin_reset_password(
        user_id: str, request: Request, admin: User = Depends(require_admin)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        base = "/admin/users"
        form = await request.form()
        password = str(form.get("password") or "")
        if len(password) < MIN_PASSWORD_LENGTH:
            return _redirect_with(
                f"Пароль должен быть не короче {MIN_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        if password_is_too_long(password):
            return _redirect_with(
                f"Пароль должен быть не длиннее {MAX_PASSWORD_LENGTH} символов.",
                "error",
                base=base,
            )
        target = await run_in_threadpool(store.get_user, user_id)
        if target is None:
            return _redirect_with("Пользователь не найден.", "error", base=base)
        await run_in_threadpool(store.set_password, user_id, password)
        # Force re-login everywhere with the new password.
        await run_in_threadpool(store.delete_sessions_for_user, user_id)
        return _redirect_with(
            f"Пароль пользователя “{target.username}” обновлён; его сессии завершены.",
            "ok",
            base=base,
        )

    @app.post("/admin/users/{user_id}/toggle-active")
    async def admin_toggle_active(
        user_id: str, request: Request, admin: User = Depends(require_admin)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        base = "/admin/users"
        if user_id == admin.id:
            return _redirect_with(
                "Нельзя отключить собственную учётную запись.", "error", base=base
            )
        target = await run_in_threadpool(store.get_user, user_id)
        if target is None:
            return _redirect_with("Пользователь не найден.", "error", base=base)
        updated = await run_in_threadpool(store.set_active, user_id, not target.active)
        if updated is None:
            return _redirect_with("Пользователь не найден.", "error", base=base)
        if not updated.active:
            # A disabled account must not keep live sessions.
            await run_in_threadpool(store.delete_sessions_for_user, user_id)
        state = "включён" if updated.active else "отключён"
        return _redirect_with(f"Пользователь “{updated.username}” {state}.", "ok", base=base)

    @app.post("/admin/mappings/{mapping_id}/delete")
    async def admin_delete_mapping(
        mapping_id: str, request: Request, admin: User = Depends(require_admin)
    ) -> RedirectResponse:
        store: RelayStore = request.app.state.store
        removed = await run_in_threadpool(store.remove_mapping_for_user, mapping_id, admin)
        if removed is None:
            return _redirect_with("Mapping not found.", "error")
        return _redirect_with(
            f"Deleted mapping for channel {removed.source_channel_id}."
        )

    return app


app = create_app()


if __name__ == "__main__":
    # Convenience for local development: `python -m app.main`
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=get_settings().port)
