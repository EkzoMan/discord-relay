"""Discord gateway client that relays channel messages to webhooks."""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Sequence
from datetime import datetime

import discord
import httpx

from .settings import Settings
from .store import RelayStore
from .webhooks import DEFAULT_TIMEOUT, MAX_EMBEDS, send_to_webhook

logger = logging.getLogger(__name__)

#: Header for the attachments section (kept as specified: "Вложения:").
ATTACHMENTS_HEADER = "Вложения:"

#: Recently relayed message ids are remembered so that a later
#: ``MESSAGE_UPDATE`` of an already-relayed message does not duplicate it.
_RELAYED_CACHE_SIZE = 4096

#: Keys the webhook ``embeds`` payload accepts.  Everything else that
#: ``discord.Embed.to_dict()`` may carry (``content_scan_version``,
#: ``proxy_url``/``placeholder``/``flags`` inside media objects, ...) is
#: dropped so Discord can never reject the forwarded embed.
_EMBED_KEYS = frozenset(
    {
        "title", "type", "description", "url", "timestamp", "color",
        "footer", "image", "thumbnail", "video", "gif_video", "provider",
        "author", "fields",
    }
)
_MEDIA_KEYS = frozenset({"url", "width", "height"})
_FOOTER_KEYS = frozenset({"text", "icon_url"})
_AUTHOR_KEYS = frozenset({"name", "url", "icon_url"})
_PROVIDER_KEYS = frozenset({"name", "url"})
_FIELD_KEYS = frozenset({"name", "value", "inline"})
_NESTED_WHITELIST: dict[str, frozenset[str]] = {
    "image": _MEDIA_KEYS, "thumbnail": _MEDIA_KEYS, "video": _MEDIA_KEYS,
    "gif_video": _MEDIA_KEYS, "footer": _FOOTER_KEYS, "author": _AUTHOR_KEYS,
    "provider": _PROVIDER_KEYS,
}


def build_relay_content(content: str | None, attachment_urls: Sequence[str]) -> str:
    """Compose the webhook message body from text and attachment URLs.

    Returns an empty string when there is nothing worth relaying.
    """
    parts: list[str] = []
    if content:
        parts.append(content)
    if attachment_urls:
        parts.append(ATTACHMENTS_HEADER + "\n" + "\n".join(attachment_urls))
    return "\n\n".join(parts).strip()


def _jsonable(value: object) -> object:
    """Convert values httpx cannot serialize (embed timestamps are datetimes)."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _clean_embed(raw: dict) -> dict:
    """Whitelist + sanitize a single embed dict for webhook POSTing."""
    clean: dict = {}
    for key, value in raw.items():
        if key not in _EMBED_KEYS or value in (None, "", [], {}):
            continue
        if key == "fields" and isinstance(value, list):
            value = [
                {k: v for k, v in field.items() if k in _FIELD_KEYS}
                for field in value
                if isinstance(field, dict) and field.get("name") and field.get("value")
            ]
            if not value:
                continue
        elif isinstance(value, dict):
            allowed = _NESTED_WHITELIST.get(key)
            if allowed is None:
                continue
            value = {
                k: _jsonable(v) for k, v in value.items()
                if k in allowed and v not in (None, "", [], {})
            }
            if not value:
                continue
        else:
            value = _jsonable(value)
        clean[key] = value
    return clean


def collect_relay_embeds(message: discord.Message) -> list[dict]:
    """Return up to :data:`MAX_EMBEDS` embeds as webhook-safe dicts.

    Feed bots (zKillboard/Killtracker and friends) put *all* of the content
    into rich embeds and leave ``message.content`` empty — forwarding embeds
    verbatim is what makes relaying such channels possible at all.
    """
    embeds: list[dict] = []
    for embed in list(getattr(message, "embeds", None) or [])[:MAX_EMBEDS]:
        try:
            cleaned = _clean_embed(embed.to_dict())
        except Exception:
            logger.debug("Skipping unloadable embed on message id=%s", message.id)
            continue
        if cleaned:
            embeds.append(cleaned)
    return embeds


class RelayClient(discord.Client):
    """A bare ``discord.Client`` (no commands framework) that forwards
    messages according to the mappings held in a :class:`RelayStore`."""

    def __init__(
        self,
        store: RelayStore,
        settings: Settings,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        # ``guilds`` delivers guild/channel/role events; ``guild_messages``
        # is the subscription that actually makes the gateway send
        # MESSAGE_CREATE / MESSAGE_UPDATE (on_message never fires without
        # it).  ``message_content`` only unmasks message text and is
        # privileged: it must also be enabled for the bot in the Discord
        # developer portal.
        intents = discord.Intents(guilds=True, guild_messages=True, message_content=True)
        super().__init__(intents=intents)
        self._store = store
        self._settings = settings
        self._http = http_client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        self._owns_http = http_client is None
        #: Bounded FIFO of message ids already relayed (edit dedup).
        self._relayed_ids: OrderedDict[int, None] = OrderedDict()

    async def close(self) -> None:
        """Close the shared httpx session as well, then the gateway."""
        if self._owns_http and not self._http.is_closed:
            await self._http.aclose()
        await super().close()

    async def on_ready(self) -> None:
        if self.user is not None:
            logger.info("Relay bot connected as %s (id=%s)", self.user, self.user.id)

    async def on_message(self, message: discord.Message) -> None:
        try:
            await self._relay_message(message)
        except Exception:
            # A single bad message must never tear down the gateway task.
            logger.exception("Unexpected error while relaying message id=%s", message.id)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        """Relay messages that were empty when posted but filled in via an
        edit — the classic feed-bot pattern (Killtracker POSTs a placeholder,
        then PATCHes the embed).  A message already relayed on create is NOT
        re-relayed on edit."""
        try:
            await self._relay_message(after, is_edit=True)
        except Exception:
            logger.exception(
                "Unexpected error while relaying edited message id=%s", after.id
            )

    def _remember_relayed(self, message_id: int) -> None:
        self._relayed_ids[message_id] = None
        while len(self._relayed_ids) > _RELAYED_CACHE_SIZE:
            self._relayed_ids.popitem(last=False)

    async def _relay_message(
        self, message: discord.Message, *, is_edit: bool = False
    ) -> None:
        if not self._settings.allow_bot_messages and message.author.bot:
            logger.debug("Ignoring bot message id=%s (RELAY_ALLOW_BOT_MESSAGES is off)", message.id)
            return
        if not self._settings.allow_webhook_messages and message.webhook_id is not None:
            # Likely a webhook post bouncing back — ignore to prevent loops.
            logger.debug("Ignoring webhook message id=%s to avoid relay loops", message.id)
            return
        if is_edit and message.id in self._relayed_ids:
            logger.debug("Ignoring edit of already-relayed message id=%s", message.id)
            return

        # Several users may each relay the same source channel; every mapping
        # gets its own webhook copy.
        mappings = self._store.get_all_by_channel(message.channel.id)
        if not mappings:
            return

        text = build_relay_content(
            message.content, [attachment.url for attachment in message.attachments]
        )
        embeds = collect_relay_embeds(message)
        if not text and not embeds:
            logger.debug("Message id=%s has no relayable content", message.id)
            return

        username = message.author.display_name or message.author.name
        avatar_url = message.author.display_avatar.url

        any_ok = False
        for mapping in mappings:
            try:
                ok = await send_to_webhook(
                    mapping.target_webhook_url,
                    username=username,
                    avatar_url=avatar_url,
                    content=text,
                    embeds=embeds,
                    http_client=self._http,
                )
            except Exception:
                # One broken mapping must not stop the others.
                ok = False
                logger.exception(
                    "Unexpected error relaying message %s via mapping %s",
                    message.id,
                    mapping.id[:8],
                )
            # The webhook URL itself is never logged (it embeds a secret token).
            if ok:
                any_ok = True
                logger.info(
                    "Relayed message %s from channel %s via mapping %s",
                    message.id,
                    message.channel.id,
                    mapping.id[:8],
                )
            else:
                logger.warning(
                    "Failed to relay message %s from channel %s via mapping %s",
                    message.id,
                    message.channel.id,
                    mapping.id[:8],
                )
        if any_ok:
            self._remember_relayed(message.id)


async def run_relay_bot(
    store: RelayStore,
    settings: Settings,
    *,
    client: RelayClient | None = None,
) -> RelayClient | None:
    """Create and run the relay client until it exits.

    Suitable for ``asyncio.create_task(run_relay_bot(store, settings))``.
    Returns the (already closed) client, or ``None`` when no token is set.
    """
    if not settings.discord_bot_token:
        logger.warning("DISCORD_BOT_TOKEN is not set; the relay bot will not start.")
        return None

    relay_client = client or RelayClient(store, settings)
    try:
        # log_handler=None: keep discord.py from installing its own root
        # handler; the app configures logging from RELAY_LOG_LEVEL instead.
        await relay_client.start(settings.discord_bot_token)
    except discord.LoginFailure:
        logger.error("Discord rejected DISCORD_BOT_TOKEN; the relay bot is not running.")
    except discord.DiscordException:
        logger.exception("The relay bot stopped because of a Discord error.")
    finally:
        if not relay_client.is_closed():
            try:
                await relay_client.close()
            except Exception:
                logger.exception("Error while closing the Discord client")
    return relay_client
