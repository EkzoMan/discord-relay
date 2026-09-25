"""Route-level tests against the FastAPI app with a temp config path.

The app is built through the ``create_app`` factory with injected settings
and store, so no env vars, Discord connection, or network access is needed.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.models import RelayMapping
from app.settings import Settings
from app.store import ConfigStore

VALID_URL = "https://discord.com/api/webhooks/1001/secrettok-abcdefghijklmn"
CHANNEL = "123456789012345678"


def mapping_form(name="announcements", channel_id=CHANNEL, url=VALID_URL) -> dict:
    return {"name": name, "source_channel_id": channel_id, "target_webhook_url": url}


def test_dashboard_empty_store(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Discord Relay" in response.text
    assert "No mappings yet" in response.text


def test_health_is_public_json(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_status_endpoint(client, store):
    store.add(RelayMapping(name="x", source_channel_id=5, target_webhook_url=VALID_URL))
    data = client.get("/status").json()
    assert data["bot_enabled"] is False  # no token in tests
    assert data["bot_running"] is False
    assert data["mappings"] == 1


def test_post_mapping_creates_it_and_masks_token(client, store):
    response = client.post("/mappings", data=mapping_form(), follow_redirects=True)
    assert response.status_code == 200

    mappings = store.list_mappings()
    assert len(mappings) == 1
    assert mappings[0].source_channel_id == int(CHANNEL)

    # The channel shows up in the dashboard, but the webhook token stays masked.
    assert CHANNEL in response.text
    assert "secretto…" in response.text  # first 8 token chars are shown
    assert "secrettok-abcdefghijklmn" not in response.text  # full token is never rendered


def test_post_mapping_rejects_duplicate_channel(client, store):
    client.post("/mappings", data=mapping_form(), follow_redirects=True)
    response = client.post(
        "/mappings", data=mapping_form(name="dupe"), follow_redirects=True
    )
    assert response.status_code == 200
    assert "already exists" in response.text
    assert len(store.list_mappings()) == 1


def test_post_mapping_rejects_bad_webhook_url(client, store):
    response = client.post(
        "/mappings",
        data=mapping_form(url="https://evil.example.com/steal"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Invalid mapping" in response.text
    assert store.list_mappings() == []


def test_post_mapping_rejects_bad_channel_id(client, store):
    response = client.post(
        "/mappings", data=mapping_form(channel_id="not-a-number"), follow_redirects=True
    )
    assert "Invalid mapping" in response.text
    assert store.list_mappings() == []


def test_delete_mapping(client, store):
    mapping = store.add(
        RelayMapping(name="gone", source_channel_id=42, target_webhook_url=VALID_URL)
    )
    response = client.post(f"/mappings/{mapping.id}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert "Deleted mapping" in response.text
    assert store.list_mappings() == []


def test_delete_unknown_mapping(client):
    response = client.post("/mappings/nope/delete", follow_redirects=True)
    assert "not found" in response.text


def test_basic_auth_enforced_when_configured(tmp_path):
    settings = Settings(
        discord_bot_token=None,
        relay_config_path=str(tmp_path / "config.json"),
        port=8000,
        ui_username="admin",
        ui_password="s3cret",
        allow_bot_messages=False,
        log_level="INFO",
    )
    store = ConfigStore(settings.relay_config_path)
    store.load()
    authed_app = create_app(settings=settings, store=store)

    with TestClient(authed_app) as authed_client:
        assert authed_client.get("/").status_code == 401
        assert authed_client.get("/health").status_code == 401
        assert authed_client.get("/", auth=("admin", "wrong")).status_code == 401

        ok = authed_client.get("/", auth=("admin", "s3cret"))
        assert ok.status_code == 200

        created = authed_client.post(
            "/mappings", data=mapping_form(), auth=("admin", "s3cret"),
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert len(store.list_mappings()) == 1
        # Unauthenticated POST is rejected as well.
        rejected = authed_client.post(
            "/mappings", data=mapping_form(channel_id="777"), follow_redirects=False
        )
        assert rejected.status_code == 401
        assert len(store.list_mappings()) == 1
