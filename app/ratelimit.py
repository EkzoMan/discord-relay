"""In-memory login attempt throttle (single-process friendly, stdlib only).

Design notes
------------
- The app ships as one uvicorn process (see Dockerfile), so a process-local
  dict is enough; no Redis dependency. If the deployment ever scales to
  multiple workers/replicas, this class is the single swap point (keep the
  interface, move the state into a shared store).
- Bucket key = normalized (lowercased, stripped) username + client IP, so a
  targeted password spray on one account is not trivially bypassed by simply
  switching accounts from the same host, and one noisy neighbour cannot lock
  everybody else out of an unrelated account behind a shared NAT.
- Fixed window: ``max_attempts`` failures inside ``window_seconds`` lock the
  key out for another ``window_seconds``. A successful login clears the key.
- The clock is injectable (``now`` callable) so tests control time instead of
  sleeping, and so monotonic time can be swapped if ever needed.
- Privacy: nothing here logs; the key itself (username) is never surfaced in
  responses — only the generic lockout message is.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


def normalize_login_key(username: str, client_ip: str | None) -> str:
    """Build the rate-limit bucket key: lowercase username + client IP."""
    return f"{(username or '').strip().lower()}|{client_ip or 'unknown'}"


#: Safety cap on distinct tracked keys; expired entries are purged opportunistically.
_MAX_KEYS = 4096


@dataclass
class _Bucket:
    failures: int = 0
    window_start: float = 0.0
    locked_until: float = 0.0


class LoginRateLimiter:
    """Track failed login attempts and lock abusive (user, ip) pairs."""

    def __init__(
        self,
        max_attempts: int = 10,
        window_seconds: float = 15 * 60,
        *,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.max_attempts = int(max_attempts)
        self.window_seconds = float(window_seconds)
        self._now = now
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    # ------------------------------------------------------------------ #

    def is_locked(self, key: str) -> bool:
        """True while *key* is inside its lockout period."""
        now = self._now()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return False
            if bucket.locked_until > now:
                return True
            # Lockout has elapsed, or the failure window rolled over: forget.
            if bucket.locked_until and bucket.locked_until <= now:
                del self._buckets[key]
            elif now - bucket.window_start >= self.window_seconds:
                del self._buckets[key]
            return False

    def register_failure(self, key: str) -> bool:
        """Record a failed attempt for *key*.

        Returns True when *this very attempt* tripped the lockout, so callers
        can show the throttle message immediately instead of a plain
        "invalid credentials" on attempt N.
        """
        now = self._now()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= _MAX_KEYS:
                    self._purge(now)
                bucket = _Bucket(window_start=now)
                self._buckets[key] = bucket
            if bucket.locked_until > now:
                # Already locked: keep the original unlock time, do not extend.
                return True
            if bucket.locked_until:  # lock just expired
                bucket.locked_until = 0.0
            if now - bucket.window_start >= self.window_seconds:
                # Old window: start fresh.
                bucket.window_start = now
                bucket.failures = 0
            bucket.failures += 1
            if bucket.failures >= self.max_attempts:
                bucket.locked_until = now + self.window_seconds
                return True
            return False

    def register_success(self, key: str) -> None:
        """A successful login clears the failure history for *key*."""
        with self._lock:
            self._buckets.pop(key, None)

    def reset(self) -> None:
        """Drop all state (test helper; also handy for a manual nudge)."""
        with self._lock:
            self._buckets.clear()

    # ------------------------------------------------------------------ #

    def _purge(self, now: float) -> None:
        """Remove every key that is neither locked nor inside its window.
        Caller must hold ``self._lock``."""
        cutoff = now - self.window_seconds
        stale = [
            key
            for key, bucket in self._buckets.items()
            if bucket.locked_until <= now and bucket.window_start < cutoff
        ]
        for key in stale:
            del self._buckets[key]
