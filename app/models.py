"""Pydantic models for relay mappings and their validation rules."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Only real Discord webhook endpoints are accepted. This prevents the bot
#: from being pointed at arbitrary URLs through the UI.
WEBHOOK_URL_PREFIXES: tuple[str, ...] = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
)


class _MappingFields(BaseModel):
    """Fields shared by the create payload and the persisted mapping."""

    model_config = ConfigDict(str_strip_whitespace=True)

    #: Short human label; may be empty.
    name: str = Field(default="", max_length=64)
    #: Discord channel IDs are positive snowflakes.
    source_channel_id: int = Field(gt=0)
    target_webhook_url: str = Field(min_length=1)

    @field_validator("target_webhook_url")
    @classmethod
    def _validate_webhook_url(cls, value: str) -> str:
        if not value.startswith(WEBHOOK_URL_PREFIXES):
            raise ValueError(
                "Webhook URL must start with https://discord.com/api/webhooks/ "
                "or https://discordapp.com/api/webhooks/"
            )
        return value


class RelayMappingCreate(_MappingFields):
    """Validated payload submitted from the 'add mapping' form / API."""


class RelayMapping(_MappingFields):
    """A persisted relay rule: forward source channel -> target webhook."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
