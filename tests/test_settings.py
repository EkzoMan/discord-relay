"""Settings loading: new admin/session vars plus the deprecated
UI_USERNAME/UI_PASSWORD compatibility path."""

from __future__ import annotations

import pytest

from app.settings import Settings, load_settings

_VARS = (
    "ADMIN_USERNAME",
    "ADMIN_PASSWORD",
    "RELAY_DB_PATH",
    "SESSION_COOKIE_NAME",
    "SESSION_COOKIE_SECURE",
    "SESSION_TTL_HOURS",
    "LOGIN_MAX_ATTEMPTS",
    "LOGIN_LOCKOUT_MINUTES",
    "UI_USERNAME",
    "UI_PASSWORD",
    "RELAY_CONFIG_PATH",
    "DISCORD_BOT_TOKEN",
    "RELAY_ALLOW_EMBEDS",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def test_defaults():
    settings = load_settings()
    assert settings.admin_username == "admin"
    assert settings.admin_password is None
    assert settings.relay_db_path == "/data/relay.db"
    assert settings.session_cookie_name == "relay_session"
    assert settings.session_ttl_hours == 168
    assert settings.session_cookie_secure == "auto"
    assert settings.login_max_attempts == 10
    assert settings.login_lockout_minutes == 15
    assert settings.auth_required is True


def test_admin_vars_win(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "root")
    monkeypatch.setenv("ADMIN_PASSWORD", "new-pass")
    monkeypatch.setenv("UI_USERNAME", "old")
    monkeypatch.setenv("UI_PASSWORD", "old-pass")
    settings = load_settings()
    assert settings.admin_username == "root"
    assert settings.admin_password == "new-pass"


def test_ui_basic_vars_bootstrap_admin(monkeypatch):
    """Deprecated UI_USERNAME/UI_PASSWORD become the admin bootstrap."""
    monkeypatch.setenv("UI_USERNAME", "legacyadmin")
    monkeypatch.setenv("UI_PASSWORD", "legacypass")
    settings = load_settings()
    assert settings.admin_username == "legacyadmin"
    assert settings.admin_password == "legacypass"


def test_ui_vars_alone_without_username_are_not_bootstrap(monkeypatch):
    """A lone UI_PASSWORD (no UI_USERNAME) must NOT silently become admin
    credentials; the old Basic vars are optional and never required."""
    monkeypatch.setenv("UI_PASSWORD", "legacypass")
    settings = load_settings()
    assert settings.admin_password is None
    assert settings.admin_username == "admin"


def test_session_ttl_parsed(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_HOURS", "24")
    assert load_settings().session_ttl_hours == 24


def test_login_throttle_env_overrides(monkeypatch):
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("LOGIN_LOCKOUT_MINUTES", "30")
    settings = load_settings()
    assert settings.login_max_attempts == 5
    assert settings.login_lockout_minutes == 30


def test_invalid_throttle_number_raises(monkeypatch):
    monkeypatch.setenv("LOGIN_MAX_ATTEMPTS", "lots")
    with pytest.raises(ValueError):
        load_settings()


def test_session_cookie_secure_parsed_case_insensitive(monkeypatch):
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "TRUE")
    assert load_settings().session_cookie_secure == "true"
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "False")
    assert load_settings().session_cookie_secure == "false"


def test_session_cookie_secure_bad_value_falls_back_to_auto(monkeypatch):
    """A typo must not crash startup nor silently disable the Secure flag."""
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "sometimes")
    assert load_settings().session_cookie_secure == "auto"


def test_allow_embeds_loader_default_matches_dataclass(monkeypatch):
    """Loader default and dataclass default MUST be identical (True): a
    mismatch silently changes behavior for direct Settings() construction."""
    monkeypatch.delenv("RELAY_ALLOW_EMBEDS", raising=False)
    assert load_settings().allow_embeds is True
    assert Settings.__dataclass_fields__["allow_embeds"].default is True
    # Explicit opt-out works like the other relay flags.
    monkeypatch.setenv("RELAY_ALLOW_EMBEDS", "false")
    assert load_settings().allow_embeds is False
