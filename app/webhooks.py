"""Send messages to Discord webhooks via httpx.

Security note: a webhook URL contains a secret token, so it must never be
written to logs — including through exception strings, which httpx fills
with the full request URL. We only ever log the exception *type* and HTTP
status codes here.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

MAX_USERNAME_LENGTH = 80
MAX_CONTENT_LENGTH = 2000
DEFAULT_TIMEOUT = 10.0


async def send_to_webhook(
    webhook_url: str,
    *,
    username: str,
    avatar_url: str | None,
    content: str,
    http_client: httpx.AsyncClient | None = None,
) -> bool:
    """POST a message to a Discord webhook. Returns True on a 2xx response.

    ``http_client`` lets callers share a connection pool; when omitted a
    short-lived client is created and closed for this single request.
    """
    payload = {
        "username": (username or "Unknown")[:MAX_USERNAME_LENGTH],
        "avatar_url": avatar_url,
        "content": (content or "")[:MAX_CONTENT_LENGTH],
        # Never resolve mentions/roles/everyone pings from relayed content.
        "allowed_mentions": {"parse": []},
    }

    owns_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await client.post(webhook_url, json=payload)
    except httpx.HTTPError as exc:
        # Only the exception class: str(exc) would leak the webhook URL.
        logger.warning("Webhook request failed (%s)", exc.__class__.__name__)
        return False
    else:
        if 200 <= response.status_code < 300:
            return True
        logger.warning("Webhook rejected the message with HTTP %s", response.status_code)
        return False
    finally:
        if owns_client:
            await client.aclose()
