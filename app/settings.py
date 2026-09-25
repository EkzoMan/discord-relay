"""Application settings loaded from environment variables.

All configuration comes from the environment so that secrets (bot token,
webhook URLs, UI password) never live in source control. See ``.env.example``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

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


@dataclass(frozen=True)
class Settings:
    """Immutable runtime configuration."""

    #: Optional for pure web-UI development; required to actually relay.
    discord_bot_token: str | None
    #: Path of the JSON file holding relay mappings (persistent in Docker).
    relay_config_path: str
    #: Port the uvicorn server listens on.
    port: int
    #: HTTP Basic credentials for the UI/API. Auth is enforced only when
    #: *both* username and password are set.
    ui_username: str | None
    ui_password: str | None
    #: When False, messages sent by bots are ignored by the relay.
    allow_bot_messages: bool
    #: Python logging level name, e.g. INFO / DEBUG.
    log_level: str

    @property
    def ui_auth_enabled(self) -> bool:
        return bool(self.ui_username and self.ui_password)


def load_settings() -> Settings:
    """Read settings from the environment (no caching)."""
    return Settings(
        discord_bot_token=_env_str("DISCORD_BOT_TOKEN"),
        relay_config_path=_env_str("RELAY_CONFIG_PATH", "/data/config.json") or "/data/config.json",
        port=_env_int("PORT", 8000),
        ui_username=_env_str("UI_USERNAME"),
        ui_password=_env_str("UI_PASSWORD"),
        allow_bot_messages=_env_bool("RELAY_ALLOW_BOT_MESSAGES", False),
        log_level=(_env_str("RELAY_LOG_LEVEL", "INFO") or "INFO").upper(),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (call ``get_settings.cache_clear()`` in tests
    after mutating the environment)."""
    return load_settings()
