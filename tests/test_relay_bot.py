"""Offline tests for the relay bot's multi-mapping fan-out.

Several users may each relay the same source channel; every mapping must get
its own webhook copy, a failing webhook must not block the others, and the
loop/bot protections must keep working. The httpx client is fully faked.
"""

from __future__ import annotations

import dataclasses
import types
from datetime import datetime, timezone

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
    mid: int = 999,
    embeds: list | None = None,
) -> types.SimpleNamespace:
    author = types.SimpleNamespace(
        bot=author_bot,
        name="someone",
        display_name="Someone",
        display_avatar=types.SimpleNamespace(url="https://cdn/av.png"),
    )
    return types.SimpleNamespace(
        id=mid,
        author=author,
        webhook_id=webhook_id,
        channel=types.SimpleNamespace(id=channel_id),
        content=content,
        attachments=[],
        embeds=list(embeds or []),
    )


class FakeHttpClient:
    """Stands in for httpx.AsyncClient; records POST urls, can fail some."""

    def __init__(self, fail_urls: tuple[str, ...] = ()) -> None:
        self.calls: list[str] = []
        self.payloads: list[dict] = []
        self.fail_urls = set(fail_urls)

    async def post(self, url, *, json=None, **kwargs):
        self.calls.append(url)
        self.payloads.append(json or {})
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


# --------------------------------------------------------------------------- #
# Embed-only feed messages (Killtracker/zKillboard pattern) and edit handling
# --------------------------------------------------------------------------- #


class FakeEmbed:
    """Mimics discord.Embed: the relay pipeline only calls .to_dict()."""

    def __init__(self, raw: dict) -> None:
        self._raw = raw

    def to_dict(self) -> dict:
        return dict(self._raw)


#: Real-world shaped embed: datetime timestamp, non-whitelisted keys
#: (content_scan_version), proxy fields inside media objects - all must be
#: sanitized away so Discord accepts the forwarded embed.
ZKB_EMBED = {
    "type": "rich",
    "title": "P-ZMZV | HOLD MY PROBS | Fleetkill",
    "description": "lost their **Vedmak** in **P-ZMZV** worth 136.62m ISK",
    "url": "https://zkillboard.com/kill/138695965/",
    "timestamp": datetime(2026, 9, 25, 22, 41, 53, tzinfo=timezone.utc),
    "thumbnail": {
        "width": 128, "height": 128,
        "url": "https://images.evetech.net/alliances/99012122/logo",
        "proxy_url": "https://images-ext-1.discordapp.net/external/x",
        "placeholder_version": 1, "flags": 0,
    },
    "footer": {
        "text": "zKillboard",
        "icon_url": "https://auth.scan-stakan.com/zkb_icon.png",
        "proxy_icon_url": "https://images-ext-1.discordapp.net/external/y",
    },
    "author": {
        "name": "Weapons Of Mass Production.",
        "url": "https://zkillboard.com/alliance/99010468/",
        "icon_url": "https://images.evetech.net/alliances/99010468/logo",
        "proxy_icon_url": "https://images-ext-1.discordapp.net/external/z",
    },
    "color": 4243520,
    "content_scan_version": 4,
}


@pytest.mark.asyncio
async def test_embed_only_message_is_relayed_with_embeds(store, settings):
    """The Killtracker case: empty content, rich embed -> must relay, with
    the embed sanitized (no datetime, no proxy/unknown keys)."""
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)

    await client._relay_message(fake_message(content="", embeds=[FakeEmbed(ZKB_EMBED)]))

    assert fake.calls == [URL_A]
    payload = fake.payloads[0]
    assert payload["content"] == ""
    embed = payload["embeds"][0]
    assert embed["title"] == "P-ZMZV | HOLD MY PROBS | Fleetkill"
    assert embed["timestamp"] == "2026-09-25T22:41:53+00:00"
    # sanitizer must strip everything Discord would reject
    assert "content_scan_version" not in embed
    assert "proxy_url" not in embed["thumbnail"]
    assert "placeholder_version" not in embed["thumbnail"]
    assert "proxy_icon_url" not in embed["footer"]
    assert embed["author"]["name"].startswith("Weapons")


@pytest.mark.asyncio
async def test_edit_relays_previously_empty_message_once(store, settings):
    """Feed-bot pattern: empty MESSAGE_CREATE, embed arrives via
    MESSAGE_UPDATE. The edit must relay; later edits must not duplicate."""
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)

    await client._relay_message(fake_message(mid=555, content=""))
    assert fake.calls == []  # nothing relayable yet -> not remembered

    filled = fake_message(mid=555, content="", embeds=[FakeEmbed(ZKB_EMBED)])
    await client._relay_message(filled, is_edit=True)
    assert fake.calls == [URL_A]

    # zkb keeps PATCHing the same kill; already relayed -> skip.
    await client._relay_message(filled, is_edit=True)
    assert fake.calls == [URL_A]


@pytest.mark.asyncio
async def test_already_relayed_message_is_not_re_relayed_on_edit(store, settings):
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    fake = FakeHttpClient()
    client = make_client(store, settings, fake)

    await client._relay_message(fake_message(mid=777))
    assert len(fake.calls) == 1

    await client._relay_message(fake_message(mid=777, content="edited"), is_edit=True)
    assert len(fake.calls) == 1  # no duplicate on edit


@pytest.mark.asyncio
async def test_webhook_feed_message_relayed_when_allowed(store, settings):
    """Realistic Killtracker: author.bot AND webhook_id set; default
    settings must IGNORE it, allowed settings must relay the embed."""
    alice = store.create_user("alice", "alice-password-1")
    store.add_mapping(
        RelayMapping(source_channel_id=CHANNEL, target_webhook_url=URL_A,
                     owner_user_id=alice.id)
    )
    zkb = fake_message(
        mid=1553175099979604119, content="", author_bot=True,
        webhook_id=1342130254658928732, embeds=[FakeEmbed(ZKB_EMBED)],
    )

    fake_default = FakeHttpClient()
    client_default = make_client(store, settings, fake_default)
    await client_default._relay_message(zkb)
    assert fake_default.calls == []  # blocked by bot/webhook filters

    permissive = dataclasses.replace(
        settings, allow_bot_messages=True, allow_webhook_messages=True
    )
    fake_open = FakeHttpClient()
    client_open = make_client(store, permissive, fake_open)
    await client_open._relay_message(zkb)
    assert fake_open.calls == [URL_A]
