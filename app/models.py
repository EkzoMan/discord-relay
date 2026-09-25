"""Pydantic models for users, relay mappings and their validation rules."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: Only real Discord webhook endpoints are accepted. This prevents the bot
#: from being pointed at arbitrary URLs through the UI.
WEBHOOK_URL_PREFIXES: tuple[str, ...] = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
)

#: Available account roles (see app/store.py access checks).
USER_ROLE: Literal["user"] = "user"
ADMIN_ROLE: Literal["admin"] = "admin"
ROLES: tuple[str, ...] = ("user", "admin")


def utc_now_iso() -> str:
    """Current UTC time as a fixed-precision ISO string (sortable + parsable)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return str(uuid4())


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
    """Validated payload submitted from the 'add mapping' form / API.

    Note: there is deliberately no ``owner_user_id`` here — ownership is
    assigned server-side from the session, never from client input.
    """


class RelayMapping(_MappingFields):
    """A persisted relay rule: forward source channel -> target webhook."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    id: str = Field(default_factory=new_id)
    #: The user who created this relay. ``(owner_user_id, source_channel_id)``
    #: is unique: several users may each relay the same source channel, but a
    #: single user may not register the same channel twice.
    owner_user_id: str = ""
    created_at: str = Field(default_factory=utc_now_iso)


class User(BaseModel):
    """A web UI account. ``password_hash`` must never leave the data layer:
    routes expose only :class:`UserPublic` / hand-picked fields."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    id: str = Field(default_factory=new_id)
    username: str = Field(min_length=1, max_length=32)
    role: Literal["user", "admin"] = USER_ROLE
    password_hash: str
    active: bool = True
    created_at: str = Field(default_factory=utc_now_iso)


class UserPublic(BaseModel):
    """User without the password hash — safe for JSON responses / templates."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    active: bool
    created_at: str

    @classmethod
    def from_user(cls, user: User) -> "UserPublic":
        return cls(
            id=user.id,
            username=user.username,
            role=user.role,
            active=user.active,
            created_at=user.created_at,
        )


class RelayMappingView(BaseModel):
    """UI-facing projection of a mapping: masked webhook + owner info.

    There is deliberately **no** ``target_webhook_url`` field, so a view model
    can never leak the full secret into a template or JSON response.
    ``owner_username`` lets admins see which user a relay belongs to.
    """

    id: str
    name: str
    source_channel_id: int
    owner_user_id: str
    owner_username: str
    masked_url: str
    created_at: str
