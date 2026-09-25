"""SQLite-backed persistence for users, sessions and relay mappings.

This replaces the old single-user JSON ``ConfigStore``. Everything lives in
one small SQLite file (``RELAY_DB_PATH``, a volume under ``/data`` in Docker)
using only the standard library. The legacy JSON config (``RELAY_CONFIG_PATH``)
is imported once into the first admin account — see :meth:`RelayStore.import_legacy_json`.

Threading model: FastAPI sync/threadpool routes and the asyncio relay bot
share one process. A single connection with ``check_same_thread=False`` is
guarded by an ``RLock``; every statement is parameterised (no SQL
interpolation anywhere). Queries are tiny indexed lookups, so serialising
them is cheaper than juggling a connection pool.

Security notes:
- Passwords are never stored; only PBKDF2 hashes (see app/auth.py).
- Session cookies are stored as SHA-256 digests, never as raw tokens.
- Webhook URLs are secrets: they are read only by the relay hot path and the
  test endpoint; routes/templates must always show the masked form.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

from .auth import (
    MAX_PASSWORD_LENGTH,
    dummy_password_verification,
    generate_session_token,
    hash_password,
    hash_session_token,
    password_is_too_long,
    verify_password,
)
from .models import ROLES, RelayMapping, User, utc_now_iso

logger = logging.getLogger(__name__)

UTC = timezone.utc

#: meta-table key set once the legacy JSON import has run.
LEGACY_IMPORT_META_KEY = "legacy_import_done"


class DuplicateChannelError(ValueError):
    """The same owner already has a mapping for this source channel.

    (Different users may each map the same channel — that is allowed.)
    """


class DuplicateUsernameError(ValueError):
    """A user with this username already exists."""


@dataclass(frozen=True)
class Session:
    """A live login session (token digest -> user)."""

    token_hash: str
    user_id: str
    created_at: str
    expires_at: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    role          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    active        INTEGER NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS mappings (
    id                 TEXT PRIMARY KEY,
    owner_user_id      TEXT NOT NULL,
    name               TEXT,
    source_channel_id  INTEGER NOT NULL,
    target_webhook_url TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id)
);
-- Uniqueness moved from "global per channel" to "per (owner, channel)":
CREATE UNIQUE INDEX IF NOT EXISTS ux_mappings_owner_channel
    ON mappings(owner_user_id, source_channel_id);
CREATE INDEX IF NOT EXISTS idx_mappings_channel ON mappings(source_channel_id);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:  # defensive: treat naive stamps as UTC
        dt = dt.replace(tzinfo=UTC)
    return dt


class RelayStore:
    """Multi-user relay configuration store (users + sessions + mappings)."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self._path = Path(db_path)
        self._lock = threading.RLock()
        # Connected lazily in initialize(): constructing the store must not
        # touch the filesystem (module import creates the default instance).
        self._conn: sqlite3.Connection | None = None

    @property
    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("RelayStore.initialize() has not been called")
        return self._conn

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def initialize(self) -> None:
        """Create parent dirs and the schema (idempotent)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(
                    str(self._path),
                    check_same_thread=False,
                    # Small DB; busy_timeout protects against two containers
                    # sharing the same volume (not a supported setup, but fail
                    # gently rather than locking errors out immediately).
                    timeout=10.0,
                )
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA foreign_keys = ON")
                # WAL keeps readers unblocked while a writer is committing.
                self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------ #
    # Row -> model helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            username=row["username"],
            role=row["role"],
            password_hash=row["password_hash"],
            active=bool(row["active"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _mapping_from_row(row: sqlite3.Row) -> RelayMapping:
        return RelayMapping(
            id=row["id"],
            owner_user_id=row["owner_user_id"],
            name=row["name"] or "",
            source_channel_id=row["source_channel_id"],
            target_webhook_url=row["target_webhook_url"],
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #

    def create_user(self, username: str, password: str, role: str = "user") -> User:
        """Create a user with a freshly hashed password."""
        username = username.strip()
        if not username or len(username) > 32:
            raise ValueError("Username must be 1-32 characters.")
        if role not in ROLES:
            raise ValueError(f"Role must be one of {ROLES}, got {role!r}")
        if not password:
            raise ValueError("Password must not be empty.")
        if password_is_too_long(password):
            raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
        user = User(
            username=username,
            role=role,
            password_hash=hash_password(password),
            active=True,
            created_at=utc_now_iso(),
        )
        with self._lock, self._db:
            try:
                self._db.execute(
                    "INSERT INTO users (id, username, role, password_hash, active, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        user.id,
                        user.username,
                        user.role,
                        user.password_hash,
                        int(user.active),
                        user.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateUsernameError(
                    f"Username {user.username!r} is already taken."
                ) from exc
        return user

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return self._user_from_row(row) if row else None

    def get_user_by_username(self, username: str) -> User | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return self._user_from_row(row) if row else None

    def list_users(self) -> list[User]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM users ORDER BY created_at, username"
            ).fetchall()
        return [self._user_from_row(row) for row in rows]

    def count_users(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def authenticate(self, username: str, password: str) -> User | None:
        """Check credentials. Returns the user on success, else ``None``.

        A non-existent username still pays the PBKDF2 cost (dummy check) so
        login timings do not reveal whether an account exists.
        """
        user = self.get_user_by_username((username or "").strip())
        if user is None:
            dummy_password_verification(password or "")
            return None
        if not verify_password(password, user.password_hash):
            return None
        if not user.active:
            logger.info("Login attempt for disabled account %s", user.username)
            return None
        return user

    def verify_user_password(self, user_id: str, password: str) -> bool:
        """Verify *password* against the stored hash of *user_id*."""
        user = self.get_user(user_id)
        if user is None:
            dummy_password_verification(password or "")
            return False
        return verify_password(password, user.password_hash)

    def set_password(self, user_id: str, new_password: str) -> bool:
        """Replace a user's password. Returns False when the user is gone."""
        if not new_password:
            raise ValueError("Password must not be empty.")
        if password_is_too_long(new_password):
            raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")
        with self._lock, self._db:
            cur = self._db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new_password), user_id),
            )
            return cur.rowcount > 0

    def set_active(self, user_id: str, active: bool) -> User | None:
        """Enable/disable an account (admin operation)."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE users SET active = ? WHERE id = ?", (int(active), user_id)
            )
        return self.get_user(user_id)

    # ------------------------------------------------------------------ #
    # Sessions (cookie tokens are stored only as SHA-256 digests)
    # ------------------------------------------------------------------ #

    def create_session(self, user_id: str, ttl_hours: float) -> str:
        """Create a session and return the raw token (shown once, to the cookie)."""
        raw_token, token_hash = generate_session_token()
        now = datetime.now(UTC)
        expires = now + timedelta(hours=ttl_hours)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (token_hash, user_id, now.isoformat(timespec="seconds"),
                 expires.isoformat(timespec="seconds")),
            )
        return raw_token

    def get_user_by_token(self, raw_token: str) -> User | None:
        """Resolve a cookie token to an active, non-expired user."""
        if not raw_token:
            return None
        token_hash = hash_session_token(raw_token)
        with self._lock:
            row = self._db.execute(
                "SELECT s.token_hash AS sh, s.expires_at AS sexp, u.*"
                " FROM sessions s JOIN users u ON u.id = s.user_id"
                " WHERE s.token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if _parse_iso(row["sexp"]) <= datetime.now(UTC):
                # Lazy cleanup of the expired session we just bumped into.
                with self._db:
                    self._db.execute(
                        "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
                    )
                return None
            if not row["active"]:
                return None
        return self._user_from_row(row)

    def delete_session(self, raw_token: str) -> bool:
        token_hash = hash_session_token(raw_token)
        with self._lock, self._db:
            cur = self._db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
            )
            return cur.rowcount > 0

    def delete_sessions_for_user(self, user_id: str, keep_token_raw: str | None = None) -> int:
        """Kill every session of a user (after password change / deactivation).

        ``keep_token_raw`` preserves exactly one live session — used when the
        user changes their own password and should stay logged in.
        """
        keep_hash = hash_session_token(keep_token_raw) if keep_token_raw else None
        with self._lock, self._db:
            if keep_hash:
                cur = self._db.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?",
                    (user_id, keep_hash),
                )
            else:
                cur = self._db.execute(
                    "DELETE FROM sessions WHERE user_id = ?", (user_id,)
                )
            return cur.rowcount

    def purge_expired_sessions(self) -> int:
        now_iso = datetime.now(UTC).isoformat(timespec="seconds")
        with self._lock, self._db:
            cur = self._db.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now_iso,)
            )
            if cur.rowcount:
                logger.info("Purged %d expired session(s).", cur.rowcount)
            return cur.rowcount

    # ------------------------------------------------------------------ #
    # Mappings
    # ------------------------------------------------------------------ #

    def add_mapping(self, mapping: RelayMapping) -> RelayMapping:
        """Persist a new mapping. Raises DuplicateChannelError when this
        owner already relays the same source channel."""
        if not mapping.owner_user_id:
            raise ValueError("Mapping must have an owner_user_id.")
        if self.get_user(mapping.owner_user_id) is None:
            raise ValueError("Unknown owner_user_id.")
        with self._lock, self._db:
            existing = self._db.execute(
                "SELECT name, id FROM mappings WHERE owner_user_id = ? AND source_channel_id = ?",
                (mapping.owner_user_id, mapping.source_channel_id),
            ).fetchone()
            if existing is not None:
                label = existing["name"] or existing["id"][:8]
                raise DuplicateChannelError(
                    f"A mapping for channel {mapping.source_channel_id} already exists "
                    f"for this user ({label})."
                )
            try:
                self._db.execute(
                    "INSERT INTO mappings"
                    " (id, owner_user_id, name, source_channel_id, target_webhook_url, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        mapping.id,
                        mapping.owner_user_id,
                        mapping.name,
                        mapping.source_channel_id,
                        mapping.target_webhook_url,
                        mapping.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:  # race on the unique index
                raise DuplicateChannelError(
                    f"A mapping for channel {mapping.source_channel_id} already exists "
                    f"for this user."
                ) from exc
        return mapping

    def get_mapping(self, mapping_id: str) -> RelayMapping | None:
        """Raw fetch (bot internals / tests). UI routes must use
        :meth:`get_mapping_for_user` to enforce access control."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM mappings WHERE id = ?", (mapping_id,)
            ).fetchone()
        return self._mapping_from_row(row) if row else None

    def get_mapping_for_user(self, mapping_id: str, user: User) -> RelayMapping | None:
        """Access-checked fetch: owner or admin only.

        Returns ``None`` both when the mapping does not exist and when it is
        owned by somebody else — callers must not render different messages
        for the two cases (no existence leak).
        """
        with self._lock:
            if user.role == "admin":
                row = self._db.execute(
                    "SELECT * FROM mappings WHERE id = ?", (mapping_id,)
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT * FROM mappings WHERE id = ? AND owner_user_id = ?",
                    (mapping_id, user.id),
                ).fetchone()
        return self._mapping_from_row(row) if row else None

    def remove_mapping_for_user(self, mapping_id: str, user: User) -> RelayMapping | None:
        """Access-checked delete: owner or admin only, same no-leak semantics."""
        mapping = self.get_mapping_for_user(mapping_id, user)
        if mapping is None:
            return None
        with self._lock, self._db:
            self._db.execute("DELETE FROM mappings WHERE id = ?", (mapping_id,))
        return mapping

    def list_mappings(self, owner_user_id: str) -> list[RelayMapping]:
        """Mappings owned by one user (dashboard order: newest first)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM mappings WHERE owner_user_id = ?"
                " ORDER BY created_at DESC, id",
                (owner_user_id,),
            ).fetchall()
        return [self._mapping_from_row(row) for row in rows]

    def list_all_with_owner(self) -> list[tuple[RelayMapping, str | None]]:
        """Every mapping joined with its owner's username (admin view)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT m.*, u.username AS owner_username"
                " FROM mappings m LEFT JOIN users u ON u.id = m.owner_user_id"
                " ORDER BY u.username, m.created_at DESC"
            ).fetchall()
        return [(self._mapping_from_row(row), row["owner_username"]) for row in rows]

    def count_mappings(self, owner_user_id: str | None = None) -> int:
        with self._lock:
            if owner_user_id is None:
                return self._db.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]
            return self._db.execute(
                "SELECT COUNT(*) FROM mappings WHERE owner_user_id = ?", (owner_user_id,)
            ).fetchone()[0]

    def get_all_by_channel(self, channel_id: int) -> list[RelayMapping]:
        """Relay hot path: every mapping for a source channel whose owner
        account is **active**.

        Several users may each relay the same channel; each gets their own
        webhook copy. Disabled accounts must not keep relaying behind the
        user's back, so the join filters mappings whose owner has been turned
        off (``u.active = 1``); the inner join also drops any orphan row whose
        owner vanished. Admin listings (``list_all_with_owner``) stay
        unaffected — disabling is invisible-neutral for oversight, live only
        for the relay pipeline. Order is stable (creation order).
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT m.* FROM mappings m"
                " JOIN users u ON u.id = m.owner_user_id"
                " WHERE m.source_channel_id = ? AND u.active = 1"
                " ORDER BY m.created_at, m.id",
                (channel_id,),
            ).fetchall()
        return [self._mapping_from_row(row) for row in rows]

    # ------------------------------------------------------------------ #
    # Bootstrap + legacy migration
    # ------------------------------------------------------------------ #

    def bootstrap_admin(self, admin_username: str, admin_password: str | None) -> None:
        """Ensure an admin account exists (see startup rules).

        - With a configured password: create the admin account if missing.
          Never override the password of an existing user.
        - No users at all and no configured password: create admin/admin and
          warn loudly that it must be changed.
        """
        with self._lock:
            if admin_password:
                if password_is_too_long(admin_password):
                    # Fail soft: a misconfigured env var must not crash startup.
                    logger.error(
                        "ADMIN_PASSWORD is longer than %d characters; bootstrap "
                        "admin %r was NOT created. Fix the environment and restart.",
                        MAX_PASSWORD_LENGTH, admin_username,
                    )
                    return
                existing = self.get_user_by_username(admin_username)
                if existing is None:
                    self.create_user(admin_username, admin_password, role="admin")
                    logger.info("Created bootstrap admin account %r.", admin_username)
                elif existing.role != "admin":
                    # An ordinary user already owns the name: leave it alone.
                    logger.warning(
                        "Username %r is taken by a non-admin account; "
                        "ADMIN_USERNAME bootstrap skipped.",
                        admin_username,
                    )
                # Existing admin: never touch the password.
                return

            if self.count_users() == 0:
                self.create_user(admin_username, "admin", role="admin")
                logger.warning(
                    "No users existed and no admin password is configured: created "
                    "default admin %r with password 'admin'. CHANGE IT IMMEDIATELY "
                    "via Account -> Change password.",
                    admin_username,
                )

    def _get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def import_legacy_json(self, config_path: str | os.PathLike[str]) -> int:
        """One-time import of the old ``{"mappings": [...]}`` JSON config.

        Imported mappings are owned by the first admin (fallback: first
        user). A ``meta`` flag records completion so restarts don't re-import.
        Returns the number of imported mappings.
        """
        if self._get_meta(LEGACY_IMPORT_META_KEY) is not None:
            return 0

        path = Path(config_path)
        if not path.exists():
            self._set_meta(LEGACY_IMPORT_META_KEY, utc_now_iso())
            return 0

        owner = self._legacy_owner()
        if owner is None:
            logger.warning(
                "Legacy config %s found but no user exists to own it; import deferred.", path
            )
            return 0

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # Log without contents; defer so the operator can fix the file.
            logger.warning("Legacy config %s unreadable/invalid; import deferred.", path)
            return 0

        entries = data.get("mappings", []) if isinstance(data, dict) else []
        imported = 0
        seen_channels: set[int] = set()
        for index, entry in enumerate(entries):
            try:
                mapping = RelayMapping.model_validate(entry)
            except ValidationError:
                # Entry content is not logged: it contains a webhook token.
                logger.warning("Skipping invalid legacy mapping #%d in %s", index, path)
                continue
            if mapping.source_channel_id in seen_channels:
                logger.warning(
                    "Duplicate legacy channel %d in config; keeping the first entry",
                    mapping.source_channel_id,
                )
                continue
            seen_channels.add(mapping.source_channel_id)
            owned = mapping.model_copy(update={"owner_user_id": owner.id})
            try:
                self.add_mapping(owned)
            except DuplicateChannelError:
                # User already re-created this mapping manually — keep theirs.
                continue
            except ValueError:
                continue
            imported += 1

        self._set_meta(LEGACY_IMPORT_META_KEY, utc_now_iso())
        if imported:
            logger.info(
                "Imported %d legacy mapping(s) from %s into SQLite (owner: %s).",
                imported, path, owner.username,
            )
        return imported

    def _legacy_owner(self) -> User | None:
        """First admin by creation time, else the first user of any role."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE role = 'admin' ORDER BY created_at, username LIMIT 1"
            ).fetchone()
            if row is None:
                row = self._db.execute(
                    "SELECT * FROM users ORDER BY created_at, username LIMIT 1"
                ).fetchone()
        return self._user_from_row(row) if row else None
