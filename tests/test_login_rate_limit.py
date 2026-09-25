"""Login rate limiting / lockout (app/ratelimit.py + the /login route).

The limiter is unit-tested with an injected fake clock (no sleeping), and the
route behaviour is tested against a real app wired with that same limiter:
429 + generic message on lockout, lockout blocks even correct credentials,
window expiry unlocks, and a successful login clears the failure history.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.main import TOO_MANY_LOGINS_MESSAGE, create_app
from app.ratelimit import LoginRateLimiter, normalize_login_key
from conftest import ADMIN_PASSWORD, ALICE_PASSWORD, login


class FakeClock:
    """Injectable monotonic clock."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --------------------------------------------------------------------- #
# Unit: LoginRateLimiter
# --------------------------------------------------------------------- #


def test_key_normalization_case_and_whitespace():
    assert normalize_login_key(" Alice ", "1.2.3.4") == normalize_login_key("alice", "1.2.3.4")
    assert normalize_login_key("alice", "1.2.3.4") != normalize_login_key("alice", "9.9.9.9")
    assert normalize_login_key("alice", None).endswith("|unknown")


def test_lockout_triggers_at_max_attempts():
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=900, now=clock)
    key = normalize_login_key("alice", "10.0.0.1")

    assert limiter.is_locked(key) is False
    assert limiter.register_failure(key) is False
    assert limiter.register_failure(key) is False
    assert limiter.register_failure(key) is True  # 3rd trip -> locked now
    assert limiter.is_locked(key) is True


def test_success_clears_failure_history():
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=900, now=clock)
    key = normalize_login_key("alice", "10.0.0.1")

    limiter.register_failure(key)
    limiter.register_failure(key)
    limiter.register_success(key)
    assert limiter.is_locked(key) is False

    # Full budget available again: two more failures still below the trip.
    assert limiter.register_failure(key) is False
    assert limiter.register_failure(key) is False
    assert limiter.register_failure(key) is True


def test_lock_expires_after_window():
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=900, now=clock)
    key = normalize_login_key("alice", "10.0.0.1")

    limiter.register_failure(key)
    limiter.register_failure(key)
    assert limiter.is_locked(key) is True

    clock.advance(899)
    assert limiter.is_locked(key) is True
    clock.advance(2)  # past the 900s lockout
    assert limiter.is_locked(key) is False

    # Fresh window after expiry.
    assert limiter.register_failure(key) is False
    assert limiter.register_failure(key) is True


def test_window_rollover_clears_stale_failures():
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=900, now=clock)
    key = normalize_login_key("alice", "10.0.0.1")

    limiter.register_failure(key)
    limiter.register_failure(key)
    clock.advance(901)  # window rolls over before the next attempt
    assert limiter.register_failure(key) is False  # counted as #1 of a new window


def test_buckets_are_isolated_per_key():
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=1, window_seconds=900, now=clock)
    key_a = normalize_login_key("alice", "10.0.0.1")
    key_b = normalize_login_key("bob", "10.0.0.1")
    key_c = normalize_login_key("alice", "10.0.0.2")

    assert limiter.register_failure(key_a) is True
    assert limiter.is_locked(key_b) is False
    assert limiter.is_locked(key_c) is False


def test_invalid_construction_rejected():
    with pytest.raises(ValueError):
        LoginRateLimiter(max_attempts=0)
    with pytest.raises(ValueError):
        LoginRateLimiter(window_seconds=0)


# --------------------------------------------------------------------- #
# Route: POST /login behaviour
# --------------------------------------------------------------------- #


def make_limited_app(settings, store, *, max_attempts=3, window_seconds=600):
    clock = FakeClock()
    limiter = LoginRateLimiter(max_attempts=max_attempts, window_seconds=window_seconds, now=clock)
    app_settings = replace(
        settings,
        login_max_attempts=max_attempts,
        login_lockout_minutes=window_seconds // 60,
    )
    app = create_app(settings=app_settings, store=store, login_limiter=limiter)
    return app, limiter, clock


def test_route_lockout_after_n_failed_logins(settings, store, alice):
    app, limiter, clock = make_limited_app(settings, store, max_attempts=3)
    with TestClient(app) as client:
        assert login(client, "alice", "bad-1").status_code == 401
        assert login(client, "alice", "bad-2").status_code == 401
        # Third failure trips the lockout -> same generic wording, HTTP 429.
        tripped = login(client, "alice", "bad-3")
        assert tripped.status_code == 429
        assert TOO_MANY_LOGINS_MESSAGE in tripped.text

        # While locked, even the *correct* credentials are refused (429).
        blocked = login(client, "alice", ALICE_PASSWORD)
        assert blocked.status_code == 429
        assert TOO_MANY_LOGINS_MESSAGE in blocked.text

        # A different username is a different bucket: unaffected.
        assert login(client, "admin", ADMIN_PASSWORD).status_code == 303

        # ...and after the window elapses alice can log in again.
        clock.advance(601)  # window_seconds is 600 in this fixture
        assert login(client, "alice", ALICE_PASSWORD).status_code == 303


def test_route_successful_login_resets_counter(settings, store, alice):
    app, limiter, clock = make_limited_app(settings, store, max_attempts=5)
    with TestClient(app) as client:
        for i in range(4):  # one short of the trip
            assert login(client, "alice", f"wrong-{i}").status_code == 401
        assert login(client, "alice", ALICE_PASSWORD).status_code == 303  # clears
        client.post("/logout")

        # Same number of failures again: without the reset this would have
        # tripped on the 5th overall.
        for i in range(4):
            assert login(client, "alice", f"again-{i}").status_code == 401
        assert login(client, "alice", ALICE_PASSWORD).status_code == 303


def test_route_lockout_keyed_by_client_ip(settings, store, alice):
    """The same account from a different IP keeps its own budget."""
    app, limiter, clock = make_limited_app(settings, store, max_attempts=2)
    with TestClient(app) as client:
        assert login(client, "alice", "bad-1").status_code == 401
        assert login(client, "alice", "bad-2").status_code == 429

        # Same username, different proxy-reported IP -> fresh bucket.
        resp = client.post(
            "/login",
            data={"username": "alice", "password": ALICE_PASSWORD},
            headers={"x-forwarded-for": "203.0.113.7"},
            follow_redirects=False,
        )
        assert resp.status_code == 303


def test_login_limiter_fixture_exposes_app_state(app, login_limiter):
    """The conftest fixture hands out the app's own limiter and starts clean."""
    assert app.state.login_limiter is login_limiter
    key = normalize_login_key("anybody", "testclient")
    assert login_limiter.is_locked(key) is False
    login_limiter.register_failure(key)
    login_limiter.reset()
    assert login_limiter.is_locked(key) is False
