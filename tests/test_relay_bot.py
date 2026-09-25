"""Offline tests for the relay bot's multi-mapping fan-out.

Several users may each relay the same source channel; every mapping must get
its own webhook copy, a failing webhook must not block the others, and the
loop/bot protections must keep working. The httpx client is fully faked.
"""

from __future__ import annotations

import dataclasses
import types

import httpx
import pytest

from app.models import RelayMapping
from app.relay_bot import RelayClient, build_relay_content

CHANNEL = 123456789012345678
URL_A = "https://discord.com/api/webhooks/1001/token-aaaa"
URL_B = "https://discord.com/api/webhooks/1001/token-bbbb"


def fake_message(
    *,
    content: str = "hello world",
    webhook_id: int | None = None,
    author_bot: bool = False,
    channel_id: int = CHANNEL,
) -> types.SimpleNamespace:
    author = types.SimpleNamespace(
        bot=author_bot,
        name="someone",
        display_name="Someone",
        display_avatar=types.SimpleNamespace(url="https://cdn/av.png"),
    )
    return types.SimpleNamespace(
        id=999,
        author=author,
        webhook_id=webhook_id,
        channel=types.SimpleNamespace(id=channel_id),
        content=content,
        attachments=[],
    )


class FakeHttpClient:
    """Stands in for httpx.AsyncClient; records POST urls, can fail some."""

    def __init__(self, fail_urls: tuple[str, ...] = ()) -> None:
        self.calls: list[str] = []
        self.fail_urls = set(fail_urls)

    async def post(self, url, *, json=None, **kwargs):
        self.calls.append(url)
        if url in self.fail_urls:
            raise httpx.ConnectError("connection refused")  # caught by webhooks.py
        return types.SimpleNamespace(status_code=204)


def make_client(store, settings, fake: FakeHttpClient) -> RelayClient:
    # Constructed inside the running event loop of each async test.
    return RelayClient(store, settings, http_client=fake)


@pytest.mark.asyncio
async def test_two_users_same_channel_get_two_webhook_sends(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    bob = store.create_user("bob", "bob-password-12")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_B,
                     owner_user_id=bob.id)
    )

    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message())

    assert set(fake.calls) == {URL_A, URL_B}
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_disabled_owner_mapping_is_not_relayed(store, settings):
    """End-to-end guarantee for the store-level filter: turning an account
    off must stop its relays immediately, other owners keep relaying."""
    alice = store.create_user("alice", "alice-password-1")
    bob = store.create_user("bob", "bob-password-12")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_B,
                     owner_user_id=bob.id)
    )

    store.set_active(bob.id, False)
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message())

    assert fake.calls == [URL_A]  # only the active owner's webhook fired

    # Re-enable: fan-out resumes with the same mapping rows.
    store.set_active(bob.id, True)
    fake2 = FakeHttpClient()
    client2 = make_client(store, settings, fake2)
    await client2._relay_message(fake_message())
    assert set(fake2.calls) == {URL_A, URL_B}


@pytest.mark.asyncio
async def test_one_failing_webhook_does_not_block_the_other(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    bob = store.create_user("bob", "bob-password-12")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_B,
                     owner_user_id=bob.id)
    )

    fake = FakeHttpClient(fail_urls=(URL_A,))
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message())

    # Both were attempted even though the first webhook "failed".
    assert set(fake.calls) == {URL_A, URL_B}


@pytest.mark.asyncio
async def test_unmapped_channel_sends_nothing(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=5, target_webhook_url=URL_A, owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message(channel_id=6))
    assert fake.calls == []


@pytest.mark.asyncio
async def test_webhook_origin_messages_are_ignored(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message(webhook_id=123))
    assert fake.calls == []  # loop protection


@pytest.mark.asyncio
async def test_bot_messages_ignored_unless_allowed(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )

    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message(author_bot=True))
    assert fake.calls == []

    allow_bots = dataclasses.replace(settings, allow_bot_messages=True)
    fake2 = FakeHttpClient()
    client2 = make_client(store, allow_bots, fake2)
    await client2._relay_message(fake_message(author_bot=True))
    assert fake2.calls == [URL_A]


@pytest.mark.asyncio
async def test_empty_content_message_is_skipped(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)
    await client._relay_message(fake_message(content=""))
    assert fake.calls == []


def test_build_relay_content_still_appends_attachments():
    text = build_relay_content("hi", ["https://cdn/one.png", "https://cdn/two.png"])
    assert text.startswith("hi\n\nВложения:")
    assert "https://cdn/two.png" in text
    assert build_relay_content(None, []) == ""
