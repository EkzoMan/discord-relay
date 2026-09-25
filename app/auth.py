"""Password hashing and session token helpers (stdlib only).

Passwords are hashed with PBKDF2-HMAC-SHA256 and a per-password random salt.
The stored format is::

    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>

so the cost parameter travels with the hash (future iterations bumps keep
working old hashes because verification uses the stored iteration count).

Session tokens are high-entropy random strings; only their SHA-256 digest is
persisted, so a database leak does not hand out live cookies.
"""

from __future__ import annotations

import hashlib
import secrets

#: PBKDF2-HMAC-SHA256 work factor for new hashes. OWASP guidance for this
#: scheme is >= 120k iterations; 210k leaves headroom while keeping login
#: latency acceptable (~50-150 ms on commodity hardware).
PBKDF2_ITERATIONS = 210_000

#: Hard cap on password length (characters). PBKDF2 re-derives the HMAC for
#: the *whole* secret on every iteration, so an unbounded password is a cheap
#: CPU-DoS vector on every hashing endpoint. Boundaries (login, admin create,
#: change/reset) must reject longer input before it reaches the hash
#: functions; the guards in :func:`hash_password` / :func:`verify_password`
#: are defense in depth.
MAX_PASSWORD_LENGTH = 1024

#: Algorithm marker inside the stored hash string.
_HASH_SCHEME = "pbkdf2_sha256"

#: Salt size in bytes (hex-encoded when stored).
_SALT_BYTES = 16


def password_is_too_long(password: str | None) -> bool:
    """True when *password* exceeds :data:`MAX_PASSWORD_LENGTH`."""
    return password is not None and len(password) > MAX_PASSWORD_LENGTH


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return a salted PBKDF2-SHA256 hash suitable for storage."""
    if iterations < 1_000:
        # Guard against an accidental "no work factor" misconfiguration.
        raise ValueError("iterations must be >= 1000")
    if password_is_too_long(password):
        # Never store a hash that ties up the CPU for minutes.
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_HASH_SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification of *password* against *stored_hash*.

    Malformed stored values simply verify as ``False`` — the DB is the only
    producer of these strings, so a broken one means tampering/corruption,
    not a user error worth a distinct message.

    Over-long candidates fail *before* any PBKDF2 work: new hashes are never
    created for them (see :func:`hash_password`), and the early return keeps
    the cost of the rejection path bounded. Existing stored hashes (short
    passwords) verify unchanged — the cap introduces no rehash/migration.
    """
    if password_is_too_long(password):
        return False
    try:
        scheme, iterations_str, salt_hex, hash_hex = stored_hash.split("$")
        if scheme != _HASH_SCHEME:
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    if iterations < 1 or not salt or not expected:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return secrets.compare_digest(candidate, expected)


def generate_session_token() -> tuple[str, str]:
    """Return ``(raw_token, token_hash_hex)``.

    The raw token goes into the user's cookie exactly once (at login); the
    hex SHA-256 digest is what gets stored in the sessions table.
    """
    raw = secrets.token_urlsafe(32)
    return raw, hash_session_token(raw)


def hash_session_token(raw_token: str) -> str:
    """SHA-256 digest of a raw session token, used as the sessions PK."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def dummy_password_verification(password: str = "dummy-password") -> bool:
    """Run a real PBKDF2 hash against a fixed dummy digest.

    Used when the username does not exist so the response time matches a
    genuine password check (mitigates username enumeration via timing).
    The work factor must equal :func:`verify_password` — hence the same
    ``PBKDF2_ITERATIONS`` constant and the same input-length guard (no
    logging of anything the client typed).
    """
    if password_is_too_long(password):
        # verify_password() would bail out early for this input too; mirror
        # that so the "unknown user" timing path stays comparable *and* cheap.
        return False
    return secrets.compare_digest(
        hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b"\x00" * _SALT_BYTES, PBKDF2_ITERATIONS
        ),
        b"\x00" * 32,
    )
