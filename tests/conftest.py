"""Shared pytest fixtures. Tests never touch the network: the Discord bot is
never started (no token), webhook sending uses fake httpx clients, and the
SQLite database / legacy JSON live in per-test tmp directories."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import create_app
from app.settings import Settings
from app.store import RelayStore

ADMIN_PASSWORD = "bootstrap-admin-pass"
ALICE_PASSWORD = "alice-password-1"
BOB_PASSWORD = "bob-password-12"


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        discord_bot_token=None,  # keeps the relay bot (and network) out of tests
        relay_config_path=str(tmp_path / "config.json"),
        port=8000,
        ui_username=None,
        ui_password=None,
        allow_bot_messages=False,
        log_level="INFO",
        admin_username="admin",
        admin_password=ADMIN_PASSWORD,
        relay_db_path=str(tmp_path / "relay.db"),
        session_cookie_name="relay_session",
        session_ttl_hours=168,
        session_cookie_secure="auto",
        # Generous budget: the shared fixtures must never trip the throttle by
        # accident. Rate-limit tests build their own low-limit settings.
        login_max_attempts=100,
        login_lockout_minutes=15,
    )


@pytest.fixture()
def store(settings: Settings) -> RelayStore:
    st = RelayStore(settings.relay_db_path)
    st.initialize()
    st.bootstrap_admin(settings.admin_username, settings.admin_password)
    return st


@pytest.fixture()
def app(settings: Settings, store: RelayStore):
    return create_app(settings=settings, store=store)


@pytest.fixture()
def client(app):
    # Context manager runs the app lifespan (bootstrap steps are idempotent).
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def login_limiter(app):
    """The app's LoginRateLimiter, explicitly reset for a clean slate.

    Each test already gets a fresh app (and limiter), but tests that hammer
    the login route grab this to make the dependency visible and to clear
    state mid-test without rebuilding the app.
    """
    limiter = app.state.login_limiter
    limiter.reset()
    return limiter


@pytest.fixture()
def second_client(app):
    """A second browser session against the same app/store (multi-user tests)."""
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


@pytest.fixture()
def admin_client(client: TestClient) -> TestClient:
    """A client logged in as the bootstrap admin."""
    response = login(client, "admin", ADMIN_PASSWORD)
    assert response.status_code == 303
    return client


@pytest.fixture()
def alice(store: RelayStore):
    return store.create_user("alice", ALICE_PASSWORD, role="user")


@pytest.fixture()
def bob(store: RelayStore):
    return store.create_user("bob", BOB_PASSWORD, role="user")
