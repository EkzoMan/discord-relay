"""Discord gateway client that relays channel messages to webhooks."""

from __future__ import annotations

import logging
from collections.abc import Sequence

import discord
import httpx

from .settings import Settings
from .store import RelayStore
from .webhooks import DEFAULT_TIMEOUT, send_to_webhook

logger = logging.getLogger(__name__)

#: Header for the attachments section (kept as specified: "Вложения:").
ATTACHMENTS_HEADER = "Вложения:"


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
        # ``guilds`` delivers guild/channel/role events; ``messages`` is the
        # subscription that actually makes the gateway send MESSAGE_CREATE
        # (on_message never fires without it).  ``message_content`` only
        # unmasks message text and is privileged: it must also be enabled for
        # the bot in the Discord developer portal.
        intents = discord.Intents(guilds=True, messages=True, guild_messages=True, message_content=True)
        super().__init__(intents=intents)
        self._store = store
        self._settings = settings
        self._http = http_client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        self._owns_http = http_client is None

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

    async def _relay_message(self, message: discord.Message) -> None:
        if not self._settings.allow_bot_messages and message.author.bot:
            logger.debug("Ignoring bot message id=%s (RELAY_ALLOW_BOT_MESSAGES is off)", message.id)
            return
        if not self._settings.allow_webhook_messages and message.webhook_id is not None:
            # Likely a webhook post bouncing back — ignore to prevent loops.
            logger.debug("Ignoring webhook message id=%s to avoid relay loops", message.id)
            return

        # Several users may each relay the same source channel; every mapping
        # gets its own webhook copy.
        mappings = self._store.get_all_by_channel(message.channel.id)
        if not mappings:
            return

        text = build_relay_content(
            message.content, [attachment.url for attachment in message.attachments]
        )
        if not text:
            logger.debug("Message id=%s has no relayable content", message.id)
            return

        username = message.author.display_name or message.author.name
        avatar_url = message.author.display_avatar.url

        for mapping in mappings:
            try:
                ok = await send_to_webhook(
                    mapping.target_webhook_url,
                    username=username,
                    avatar_url=avatar_url,
                    content=text,
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
