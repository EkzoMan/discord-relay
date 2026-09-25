"""Application settings loaded from environment variables.

All configuration comes from the environment so that secrets (bot token,
webhook URLs, admin password) never live in source control. See ``.env.example``.

Auth model: session-based login for multiple users (users/sessions live in
SQLite, see ``app/store.py``). The old optional HTTP Basic variables
(``UI_USERNAME``/``UI_PASSWORD``) are only used as a *deprecated* bootstrap
path for the first admin account.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_str(name: str, default: str | None = None) -> str | None:
    """Return an env var stripped of whitespace; empty string counts as unset."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    raw = raw.strip()
    return raw or default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in _TRUE_VALUES


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


#: Accepted values for SESSION_COOKIE_SECURE (see Settings.session_cookie_secure).
COOKIE_SECURE_MODES = ("auto", "true", "false")


def _env_cookie_secure(name: str, default: str) -> str:
    """Parse SESSION_COOKIE_SECURE leniently: unknown/garbage values fall back
    to the default with a warning — a typo must never crash the app at import
    time or silently disable the Secure flag."""
    raw = _env_str(name)
    if raw is None:
        return default
    mode = raw.lower()
    if mode not in COOKIE_SECURE_MODES:
        logger.warning(
            "%s=%r is not one of %s; falling back to %r.",
            name, raw, ", ".join(COOKIE_SECURE_MODES), default,
        )
        return default
    return mode


@dataclass(frozen=True)
class Settings:
    """Immutable runtime configuration."""

    #: Optional for pure web-UI development; required to actually relay.
    discord_bot_token: str | None
    #: Path of the *legacy* JSON file. Only read once at startup to import
    #: old single-user mappings into SQLite (see RelayStore.import_legacy_json).
    relay_config_path: str
    #: Port the uvicorn server listens on.
    port: int
    #: Deprecated. Kept only for backward compatibility: when
    #: ADMIN_USERNAME/ADMIN_PASSWORD are unset but these are set, they become
    #: the admin bootstrap credentials (a warning is logged).
    ui_username: str | None
    ui_password: str | None
    #: When False, messages sent by bots are ignored by the relay.
    allow_bot_messages: bool
    #: Python logging level name, e.g. INFO / DEBUG.
    log_level: str

    #: #: Username of the bootstrap admin account.
    admin_username: str = "admin"
    #: #: Password used to create the admin account on first startup.
    #: If unset and no users exist at all, the store falls back to
    #: admin/admin (and logs a loud warning).
    admin_password: str | None = None
    #: #: SQLite database holding users/sessions/mappings (persistent volume in Docker).
    relay_db_path: str = "/data/relay.db"
    #: Name of the session cookie.
    session_cookie_name: str = "relay_session"
    #: #: Session lifetime in hours (default 7 days).
    session_ttl_hours: int = 168
    #: Cookie ``Secure`` attribute policy: ``auto`` (set it when the request
    #: arrives over HTTPS / X-Forwarded-Proto=https), ``true`` (always),
    #: ``false`` (never — local http debugging only).
    session_cookie_secure: str = "auto"
    #: Failed logins allowed per (username + client IP) inside the window
    #: before the lockout kicks in.
    login_max_attempts: int = 10
    #: Length of the failure-counting window *and* the lockout duration,
    #: in minutes.
    login_lockout_minutes: int = 15
    allow_webhook_messages: bool = True
    @property
    def auth_required(self) -> bool:
        """Login is always required now (session-based multi-user auth).

        Replaces the old ``ui_auth_enabled`` flag, which made Basic auth
        optional; kept as a property so simple ``if settings.auth_required``
        style checks remain valid.
        """
        return True


def load_settings() -> Settings:
    """Read settings from the environment (no caching)."""
    admin_username = _env_str("ADMIN_USERNAME", "admin") or "admin"
    admin_password = _env_str("ADMIN_PASSWORD")

    # Deprecated compatibility: old Basic-auth env vars bootstrap the admin.
    legacy_username = _env_str("UI_USERNAME")
    legacy_password = _env_str("UI_PASSWORD")
    if admin_password is None and legacy_username and legacy_password:
        logger.warning(
            "UI_USERNAME/UI_PASSWORD are deprecated; using them as admin "
            "bootstrap credentials. Please switch to ADMIN_USERNAME/ADMIN_PASSWORD."
        )
        admin_username = legacy_username
        admin_password = legacy_password

    return Settings(
        discord_bot_token=_env_str("DISCORD_BOT_TOKEN"),
        relay_config_path=_env_str("RELAY_CONFIG_PATH", "/data/config.json") or "/data/config.json",
        port=_env_int("PORT", 8000),
        ui_username=legacy_username,
        ui_password=legacy_password,
        allow_bot_messages=_env_bool("RELAY_ALLOW_BOT_MESSAGES", False),
        allow_webhook_messages=_env_bool("RELAY_ALLOW_WEBHOOK_MESSAGES", False),
        log_level=(_env_str("RELAY_LOG_LEVEL", "INFO") or "INFO").upper(),
        admin_username=admin_username,
        admin_password=admin_password,
        relay_db_path=_env_str("RELAY_DB_PATH", "/data/relay.db") or "/data/relay.db",
        session_cookie_name=_env_str("SESSION_COOKIE_NAME", "relay_session") or "relay_session",
        session_ttl_hours=_env_int("SESSION_TTL_HOURS", 168),
        session_cookie_secure=_env_cookie_secure("SESSION_COOKIE_SECURE", "auto"),
        login_max_attempts=_env_int("LOGIN_MAX_ATTEMPTS", 10),
        login_lockout_minutes=_env_int("LOGIN_LOCKOUT_MINUTES", 15),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (call ``get_settings.cache_clear()`` in tests
    after mutating the environment)."""
    return load_settings()
