"""Shared pytest fixtures. Tests never touch the network: the Discord bot is
never started (no token) and webhook sending uses fake httpx clients."""

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
from app.store import ConfigStore


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
    )


@pytest.fixture()
def store(settings: Settings) -> ConfigStore:
    config_store = ConfigStore(settings.relay_config_path)
    config_store.load()
    return config_store


@pytest.fixture()
def app(settings: Settings, store: ConfigStore):
    return create_app(settings=settings, store=store)


@pytest.fixture()
def client(app):
    # Context manager runs the app lifespan (httpx pool etc.).
    with TestClient(app) as test_client:
        yield test_client
