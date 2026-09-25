"""Tests for webhook sending. httpx is fully faked via the injectable
``http_client`` parameter, so no network access is required."""

from __future__ import annotations

import httpx
import pytest

from app.webhooks import (
    MAX_CONTENT_LENGTH,
    MAX_USERNAME_LENGTH,
    send_to_webhook,
)

WEBHOOK_URL = "https://discord.com/api/webhooks/123456/abcdef-tinytoken"


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeClient:
    """Minimal stand-in for httpx.AsyncClient.post()."""

    def __init__(self, status_code: int = 204, error: Exception | None = None) -> None:
        self.status_code = status_code
        self.error = error
        self.calls: list[dict] = []

    async def post(self, url, *, json=None, **kwargs):
        self.calls.append({"url": url, "json": json})
        if self.error is not None:
            raise self.error
        return FakeResponse(self.status_code)


def send(**overrides):
    kwargs = {
        "username": "Alice",
        "avatar_url": "https://cdn.discordapp.com/avatars/1.png",
        "content": "hello world",
    }
    kwargs.update(overrides)
    return kwargs


@pytest.mark.asyncio
async def test_successful_send_returns_true_and_builds_payload():
    fake = FakeClient(status_code=204)
    ok = await send_to_webhook(WEBHOOK_URL, http_client=fake, **send())

    assert ok is True
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["url"] == WEBHOOK_URL
    payload = call["json"]
    assert payload["username"] == "Alice"
    assert payload["avatar_url"] == "https://cdn.discordapp.com/avatars/1.png"
    assert payload["content"] == "hello world"
    # Relay content must never ping anyone.
    assert payload["allowed_mentions"] == {"parse": []}


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 401, 404, 429, 500])
async def test_non_2xx_returns_false(status_code):
    fake = FakeClient(status_code=status_code)
    ok = await send_to_webhook(WEBHOOK_URL, http_client=fake, **send())
    assert ok is False


@pytest.mark.asyncio
async def test_network_error_returns_false_and_is_caught():
    fake = FakeClient(error=httpx.ConnectError("connection refused"))
    ok = await send_to_webhook(WEBHOOK_URL, http_client=fake, **send())
    assert ok is False


@pytest.mark.asyncio
async def test_username_and_content_are_truncated():
    fake = FakeClient(status_code=200)
    long_username = "u" * 120
    long_content = "x" * 3000

    ok = await send_to_webhook(
        WEBHOOK_URL,
        http_client=fake,
        **send(username=long_username, content=long_content),
    )

    assert ok is True
    payload = fake.calls[0]["json"]
    assert len(payload["username"]) == MAX_USERNAME_LENGTH
    assert len(payload["content"]) == MAX_CONTENT_LENGTH


@pytest.mark.asyncio
async def test_avatar_url_key_is_always_present():
    fake = FakeClient(status_code=204)
    await send_to_webhook(WEBHOOK_URL, http_client=fake, **send(avatar_url=None))
    assert "avatar_url" in fake.calls[0]["json"]
    assert fake.calls[0]["json"]["avatar_url"] is None
