"""Tests for the SQLite-backed multi-user store: users, sessions, mappings,
per-user isolation, admin bootstrap and the one-time legacy JSON import."""

from __future__ import annotations

import json

import pytest

from app.models import RelayMapping
from app.store import (
    DuplicateChannelError,
    DuplicateUsernameError,
    RelayStore,
)

WEBHOOK = "https://discord.com/api/webhooks/{channel}/token-{channel}"


def make_store(tmp_path) -> RelayStore:
    store = RelayStore(tmp_path / "relay.db")
    store.initialize()
    return store


def add(store: RelayStore, owner: str, channel: int, name: str = "test") -> RelayMapping:
    return store.add_mapping(
        RelayMapping(
            name=name,
            source_channel_id=channel,
            target_webhook_url=WEBHOOK.format(channel=channel),
            owner_user_id=owner,
        )
    )


# --------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------- #


def test_create_get_list_users(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1", role="user")
    store.create_user("root", "secret-pass-2", role="admin")

    assert store.get_user(alice.id) == alice
    assert store.get_user_by_username("alice").username == "alice"
    assert store.get_user_by_username("alice").password_hash.startswith("pbkdf2_sha256$")
    assert [u.username for u in store.list_users()] == ["alice", "root"]
    assert store.get_user("missing-id") is None
    assert store.count_users() == 2


def test_duplicate_username_is_rejected(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "secret-pass-1")
    with pytest.raises(DuplicateUsernameError):
        store.create_user("alice", "other-pass-123")


def test_invalid_role_and_username_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        store.create_user("alice", "secret-pass-1", role="superuser")
    with pytest.raises(ValueError):
        store.create_user("", "secret-pass-1")
    with pytest.raises(ValueError):
        store.create_user("alice", "")


def test_authenticate_ok_wrong_password_and_inactive(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "secret-pass-1")

    assert store.authenticate("alice", "secret-pass-1") is not None
    assert store.authenticate("alice", "wrong-password") is None
    assert store.authenticate("nobody", "whatever123") is None  # dummy path

    alice = store.get_user_by_username("alice")
    store.set_active(alice.id, False)
    assert store.authenticate("alice", "secret-pass-1") is None
    assert store.verify_user_password(alice.id, "secret-pass-1") is True
    assert store.verify_user_password("missing-id", "whatever123") is False


def test_set_password_changes_credentials(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    assert store.set_password(alice.id, "brand-new-pass") is True
    assert store.authenticate("alice", "secret-pass-1") is None
    assert store.authenticate("alice", "brand-new-pass") is not None
    assert store.set_password("missing-id", "whatever123") is False


# --------------------------------------------------------------------- #
# Admin bootstrap
# --------------------------------------------------------------------- #


def test_bootstrap_creates_admin_with_configured_password(tmp_path):
    store = make_store(tmp_path)
    store.bootstrap_admin("admin", "configured-pass")
    admin = store.get_user_by_username("admin")
    assert admin is not None and admin.role == "admin"

    # Running it again must NOT reset a password the admin has changed.
    store.set_password(admin.id, "changed-by-admin")
    store.bootstrap_admin("admin", "configured-pass")
    assert store.authenticate("admin", "changed-by-admin") is not None


def test_bootstrap_default_admin_when_db_empty(tmp_path):
    store = make_store(tmp_path)
    store.bootstrap_admin("admin", None)  # no configured password, no users
    assert store.authenticate("admin", "admin") is not None
    assert store.get_user_by_username("admin").role == "admin"


def test_bootstrap_does_nothing_when_users_exist(tmp_path):
    store = make_store(tmp_path)
    store.create_user("alice", "secret-pass-1", role="user")
    store.bootstrap_admin("admin", None)
    assert store.get_user_by_username("admin") is None
    assert store.count_users() == 1


# --------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------- #


def test_session_lifecycle(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    raw = store.create_session(alice.id, ttl_hours=1)

    assert store.get_user_by_token(raw).id == alice.id
    assert store.get_user_by_token("bogus-token") is None

    assert store.delete_session(raw) is True
    assert store.get_user_by_token(raw) is None
    assert store.delete_session(raw) is False


def test_session_expiry(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    raw = store.create_session(alice.id, ttl_hours=-1)  # already expired
    assert store.get_user_by_token(raw) is None
    # The expired row was cleaned lazily:
    assert store.purge_expired_sessions() == 0


def test_delete_sessions_for_user_with_keep(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    keep = store.create_session(alice.id, ttl_hours=1)
    other = store.create_session(alice.id, ttl_hours=1)

    removed = store.delete_sessions_for_user(alice.id, keep_token_raw=keep)
    assert removed == 1
    assert store.get_user_by_token(keep) is not None
    assert store.get_user_by_token(other) is None

    store.delete_sessions_for_user(alice.id)
    assert store.get_user_by_token(keep) is None


def test_disabling_user_invalidates_sessions(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    raw = store.create_session(alice.id, ttl_hours=1)
    store.set_active(alice.id, False)
    assert store.get_user_by_token(raw) is None


# --------------------------------------------------------------------- #
# Mappings: ownership + isolation
# --------------------------------------------------------------------- #


def test_duplicate_owner_channel_blocked(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    add(store, alice.id, 123)
    with pytest.raises(DuplicateChannelError):
        add(store, alice.id, 123, name="dupe")
    assert store.count_mappings(alice.id) == 1


def test_different_users_can_add_same_channel(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    bob = store.create_user("bob", "secret-pass-2")
    m_a = add(store, alice.id, 777, name="alice")
    m_b = add(store, bob.id, 777, name="bob")

    by_channel = store.get_all_by_channel(777)
    assert {m.id for m in by_channel} == {m_a.id, m_b.id}
    assert store.count_mappings(alice.id) == 1
    assert store.count_mappings(bob.id) == 1


def test_get_all_by_channel_skips_disabled_owners(tmp_path):
    """The relay hot path must ignore mappings whose owner is disabled,
    while the admin listing keeps showing them (oversight != execution)."""
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    bob = store.create_user("bob", "secret-pass-2")
    m_a = add(store, alice.id, 888, name="alice-active")
    m_b = add(store, bob.id, 888, name="bob-disabled")

    # Both active: both relay.
    assert {m.id for m in store.get_all_by_channel(888)} == {m_a.id, m_b.id}

    store.set_active(bob.id, False)
    assert [m.id for m in store.get_all_by_channel(888)] == [m_a.id]

    # Admin view is unaffected: the mapping (and its owner) stay visible.
    pairs = store.list_all_with_owner()
    assert {m.id for m, _ in pairs} == {m_a.id, m_b.id}
    assert {owner for _, owner in pairs} == {"alice", "bob"}

    # Re-enabling resumes relaying without touching the mapping rows.
    store.set_active(bob.id, True)
    assert {m.id for m in store.get_all_by_channel(888)} == {m_a.id, m_b.id}


def test_add_mapping_requires_valid_owner(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        add(store, "", 5)  # no owner at all
    with pytest.raises(ValueError):
        add(store, "ghost-user-id", 5)  # unknown owner


def test_user_access_checks_on_get_and_remove(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    bob = store.create_user("bob", "secret-pass-2")
    admin = store.create_user("root", "secret-pass-3", role="admin")
    m = add(store, alice.id, 42)

    assert store.get_mapping_for_user(m.id, alice) == m
    assert store.get_mapping_for_user(m.id, bob) is None  # isolation
    assert store.get_mapping_for_user(m.id, admin) == m  # admin sees all

    # Bob cannot delete Alice's mapping.
    assert store.remove_mapping_for_user(m.id, bob) is None
    assert store.get_mapping(m.id) is not None
    # Admin can.
    assert store.remove_mapping_for_user(m.id, admin) == m
    assert store.get_mapping(m.id) is None


def test_list_all_with_owner_includes_usernames(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    bob = store.create_user("bob", "secret-pass-2")
    add(store, alice.id, 1, name="a1")
    add(store, bob.id, 2, name="b2")

    pairs = store.list_all_with_owner()
    by_channel = {m.source_channel_id: (m.name, owner) for m, owner in pairs}
    assert by_channel == {1: ("a1", "alice"), 2: ("b2", "bob")}


def test_list_mappings_scoped_per_owner(tmp_path):
    store = make_store(tmp_path)
    alice = store.create_user("alice", "secret-pass-1")
    bob = store.create_user("bob", "secret-pass-2")
    add(store, alice.id, 1, name="a1")
    add(store, bob.id, 2, name="b1")

    assert [m.name for m in store.list_mappings(alice.id)] == ["a1"]
    assert [m.name for m in store.list_mappings(bob.id)] == ["b1"]
    assert store.count_mappings() == 2  # total


# --------------------------------------------------------------------- #
# Persistence + legacy import
# --------------------------------------------------------------------- #


def test_data_survives_reopen(tmp_path):
    path = tmp_path / "relay.db"
    first = RelayStore(path)
    first.initialize()
    alice = first.create_user("alice", "secret-pass-1")
    mapping = add(first, alice.id, 9)

    second = RelayStore(path)
    second.initialize()
    assert second.get_user_by_username("alice") is not None
    assert second.get_all_by_channel(9)[0].id == mapping.id


def test_legacy_json_import(tmp_path):
    store = make_store(tmp_path)
    admin = store.create_user("admin", "secret-pass-1", role="admin")

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "mappings": [
                    {
                        "id": "legacy-1",
                        "name": "old-rule",
                        "source_channel_id": 55,
                        "target_webhook_url": "https://discord.com/api/webhooks/55/tok1",
                    },
                    {
                        "name": "broken-entry",
                        "source_channel_id": -1,  # invalid: not gt 0
                        "target_webhook_url": "https://discord.com/api/webhooks/-1/tok2",
                    },
                    {
                        "id": "legacy-1",  # duplicate id + channel: skipped
                        "source_channel_id": 55,
                        "target_webhook_url": "https://discord.com/api/webhooks/55/tok1",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    imported = store.import_legacy_json(config)
    assert imported == 1
    mapping = store.get_all_by_channel(55)[0]
    assert mapping.id == "legacy-1"
    assert mapping.owner_user_id == admin.id
    assert mapping.name == "old-rule"

    # Idempotent: a second run (i.e. after restart) imports nothing.
    assert store.import_legacy_json(config) == 0


def test_legacy_import_absent_file_sets_flag(tmp_path):
    store = make_store(tmp_path)
    assert store.import_legacy_json(tmp_path / "does-not-exist.json") == 0
    # And does not re-run endlessly afterwards.
    assert store.import_legacy_json(tmp_path / "does-not-exist.json") == 0


def test_legacy_import_deferred_without_users(tmp_path):
    store = make_store(tmp_path)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "mappings": [
                    {
                        "source_channel_id": 5,
                        "target_webhook_url": "https://discord.com/api/webhooks/5/tok",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert store.import_legacy_json(config) == 0  # no owner yet -> deferred
    store.create_user("admin", "secret-pass-1", role="admin")
    assert store.import_legacy_json(config) == 1  # now it works
