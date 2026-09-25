"""Tests for the JSON-backed mapping store: add, duplicate prevention,
remove, atomic persistence, reload."""

from __future__ import annotations

import json

import pytest

from app.models import RelayMapping
from app.store import ConfigStore, DuplicateChannelError


def make_mapping(channel_id: int, name: str = "test") -> RelayMapping:
    return RelayMapping(
        name=name,
        source_channel_id=channel_id,
        target_webhook_url=f"https://discord.com/api/webhooks/{channel_id}/token-{channel_id}",
    )


def make_store(tmp_path) -> ConfigStore:
    store = ConfigStore(tmp_path / "config.json")
    store.load()
    return store


def test_add_list_and_get(tmp_path):
    store = make_store(tmp_path)
    mapping = store.add(make_mapping(123))

    assert store.list_mappings() == [mapping]
    assert store.get(mapping.id) == mapping
    assert store.get("does-not-exist") is None
    assert store.get_by_channel(123) == mapping
    assert store.get_by_channel(999) is None


def test_duplicate_source_channel_is_rejected(tmp_path):
    store = make_store(tmp_path)
    store.add(make_mapping(123))

    with pytest.raises(DuplicateChannelError):
        store.add(make_mapping(123, name="dupe"))

    assert len(store.list_mappings()) == 1


def test_remove_mapping(tmp_path):
    store = make_store(tmp_path)
    mapping = store.add(make_mapping(123))

    assert store.remove(mapping.id) == mapping
    assert store.list_mappings() == []
    assert store.get_by_channel(123) is None
    # Removing again is a no-op returning None.
    assert store.remove(mapping.id) is None


def test_persistence_survives_reload(tmp_path):
    # Nested directory must be created automatically by save().
    path = tmp_path / "nested" / "deep" / "config.json"
    first = ConfigStore(path)
    first.load()
    a = first.add(make_mapping(1, name="alpha"))
    b = first.add(make_mapping(2, name="beta"))

    second = ConfigStore(path)
    loaded = second.load()

    assert loaded == [a, b]
    assert second.get_by_channel(1) == a

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw.keys()) == {"mappings"}
    assert raw["mappings"][0]["source_channel_id"] == 1
    # No leftover temp files from the atomic write.
    assert not list(path.parent.glob("*.tmp"))


def test_duplicate_channels_in_file_collapse_on_load(tmp_path):
    path = tmp_path / "config.json"
    dup = {
        "mappings": [
            {
                "id": "one",
                "name": "first",
                "source_channel_id": 55,
                "target_webhook_url": "https://discord.com/api/webhooks/55/tok1",
            },
            {
                "id": "two",
                "name": "second",
                "source_channel_id": 55,
                "target_webhook_url": "https://discord.com/api/webhooks/55/tok2",
            },
        ]
    }
    path.write_text(json.dumps(dup), encoding="utf-8")

    store = ConfigStore(path)
    mappings = store.load()
    assert [m.id for m in mappings] == ["one"]


def test_load_tolerates_corrupt_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{ this is not json", encoding="utf-8")

    store = ConfigStore(path)
    assert store.load() == []

    # A corrupted file does not block subsequent writes.
    store.add(make_mapping(7))
    assert len(ConfigStore(path).load()) == 1


def test_ids_are_unique(tmp_path):
    store = make_store(tmp_path)
    m1 = store.add(make_mapping(1))
    m2 = store.add(make_mapping(2))
    assert m1.id != m2.id
