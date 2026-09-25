"""Tests for the password / session token utilities (app/auth.py)."""

from __future__ import annotations

import hashlib

import pytest

from app.auth import (
    MAX_PASSWORD_LENGTH,
    PBKDF2_ITERATIONS,
    dummy_password_verification,
    generate_session_token,
    hash_password,
    hash_session_token,
    password_is_too_long,
    verify_password,
)


def test_hash_format_and_roundtrip():
    stored = hash_password("correct horse battery staple", iterations=1500)
    scheme, iterations, salt_hex, hash_hex = stored.split("$")
    assert scheme == "pbkdf2_sha256"
    assert int(iterations) == 1500
    assert len(bytes.fromhex(salt_hex)) == 16
    assert len(bytes.fromhex(hash_hex)) == 32

    assert verify_password("correct horse battery staple", stored) is True
    assert verify_password("wrong password", stored) is False


def test_same_password_hashes_differ_thanks_to_random_salt():
    a = hash_password("dup-pw", iterations=1500)
    b = hash_password("dup-pw", iterations=1500)
    assert a != b
    assert verify_password("dup-pw", a) and verify_password("dup-pw", b)


def test_default_iterations_are_reasonable():
    assert PBKDF2_ITERATIONS >= 100_000


def test_verify_password_rejects_malformed_hashes():
    for junk in ("", "not-a-hash", "pbkdf2_sha256$1500$zz$yy", "md5$1500$aabb$ccdd", "a$b$c$d$e"):
        assert verify_password("whatever", junk) is False


def test_session_token_generation():
    raw, digest = generate_session_token()
    assert raw and len(raw) >= 32
    assert digest == hash_session_token(raw) == hashlib.sha256(raw.encode()).hexdigest()
    assert len(digest) == 64
    # Tokens are unique per call.
    assert generate_session_token()[0] != raw


# --------------------------------------------------------------------- #
# Timing equalisation + bounded hashing cost (architecture review fixes)
# --------------------------------------------------------------------- #


def test_dummy_verification_uses_real_iteration_count(monkeypatch):
    """The unknown-user dummy path must match the genuine work factor."""
    captured: dict[str, int] = {}
    real_hmac = hashlib.pbkdf2_hmac

    def spy(name, password, salt, iterations, *args, **kwargs):
        captured["iterations"] = iterations
        return real_hmac(name, password, salt, iterations, *args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", spy)
    assert dummy_password_verification("some-guess") is False
    assert captured.get("iterations") == PBKDF2_ITERATIONS


def test_dummy_verification_rejects_oversized_input_without_hashing(monkeypatch):
    """A huge login password must not pay the PBKDF2 cost on either path."""
    calls: list[int] = []
    real_hmac = hashlib.pbkdf2_hmac

    def spy(name, password, salt, iterations, *args, **kwargs):
        calls.append(iterations)
        return real_hmac(name, password, salt, iterations, *args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", spy)
    assert dummy_password_verification("x" * (MAX_PASSWORD_LENGTH + 1)) is False
    assert calls == []

    stored = hash_password("normal-pass", iterations=1500)
    assert verify_password("x" * (MAX_PASSWORD_LENGTH + 1), stored) is False


def test_unknown_user_authentication_returns_none(store):
    """Login against a non-existent account is a plain False (store layer)."""
    from conftest import ADMIN_PASSWORD

    assert store.authenticate("who-is-this", "whatever123") is None
    assert store.authenticate("   ", "") is None
    # A real account still authenticates afterwards (no state damage).
    assert store.authenticate("admin", ADMIN_PASSWORD) is not None


def test_hash_password_rejects_too_long_password():
    assert password_is_too_long("x" * (MAX_PASSWORD_LENGTH + 1)) is True
    assert password_is_too_long("x" * MAX_PASSWORD_LENGTH) is False

    with pytest.raises(ValueError):
        hash_password("x" * (MAX_PASSWORD_LENGTH + 1))


def test_max_length_password_still_hashes_and_verifies():
    """Boundary: exactly MAX_PASSWORD_LENGTH is accepted (round-trip)."""
    password = "x" * MAX_PASSWORD_LENGTH
    stored = hash_password(password, iterations=1500)
    assert verify_password(password, stored) is True
