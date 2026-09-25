"""Thread-safe JSON persistence for relay mappings.

The on-disk structure is ``{"mappings": [...]}``. Every mutation writes the
file atomically (temp file + ``os.replace``) so a crash can never leave a
half-written config behind. A ``threading.RLock`` serialises access, which
makes the store safe for both the FastAPI threadpool and the asyncio task
running the Discord gateway (operations are small, in-memory lookups plus
occasional quick file writes).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path

from pydantic import ValidationError

from .models import RelayMapping

logger = logging.getLogger(__name__)


class DuplicateChannelError(ValueError):
    """Raised when a mapping already exists for a source channel."""


class ConfigStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        # id -> mapping; dict preserves insertion order (stable UI listing).
        self._mappings: dict[str, RelayMapping] = {}

    # ------------------------------------------------------------------ #
    # Loading / saving
    # ------------------------------------------------------------------ #

    def load(self) -> list[RelayMapping]:
        """Read the config file into memory. Missing/corrupt files start
        empty rather than crashing the app (the problem is logged)."""
        with self._lock:
            self._mappings = self._read_from_disk()
            return self.list_mappings()

    def _read_from_disk(self) -> dict[str, RelayMapping]:
        try:
            raw_text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError:
            logger.exception("Could not read config file %s", self._path)
            return {}

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.error("Config file %s is not valid JSON; starting empty", self._path)
            return {}

        entries = data.get("mappings", []) if isinstance(data, dict) else []
        mappings: dict[str, RelayMapping] = {}
        seen_channels: set[int] = set()
        for index, entry in enumerate(entries):
            try:
                mapping = RelayMapping.model_validate(entry)
            except ValidationError:
                # Entry content is not logged: it contains a webhook token.
                logger.warning("Skipping invalid mapping entry #%d in %s", index, self._path)
                continue
            if mapping.source_channel_id in seen_channels:
                logger.warning(
                    "Duplicate source channel %d in config file; keeping the first entry",
                    mapping.source_channel_id,
                )
                continue
            seen_channels.add(mapping.source_channel_id)
            mappings[mapping.id] = mapping
        return mappings

    def save(self) -> None:
        """Atomically persist the current state (creates parent dirs)."""
        with self._lock:
            payload = json.dumps(
                {"mappings": [m.model_dump() for m in self._mappings.values()]},
                indent=2,
                ensure_ascii=False,
            )
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self._path.parent),
                prefix=self._path.name + ".",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_name, self._path)
            except OSError:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
                raise

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def list_mappings(self) -> list[RelayMapping]:
        with self._lock:
            return list(self._mappings.values())

    def get(self, mapping_id: str) -> RelayMapping | None:
        with self._lock:
            return self._mappings.get(mapping_id)

    def get_by_channel(self, channel_id: int) -> RelayMapping | None:
        """Relay hot path lookup: at most one mapping per channel."""
        with self._lock:
            for mapping in self._mappings.values():
                if mapping.source_channel_id == channel_id:
                    return mapping
            return None

    # ------------------------------------------------------------------ #
    # Mutations (each persisted immediately)
    # ------------------------------------------------------------------ #

    def add(self, mapping: RelayMapping) -> RelayMapping:
        with self._lock:
            for existing in self._mappings.values():
                if existing.source_channel_id == mapping.source_channel_id:
                    raise DuplicateChannelError(
                        f"A mapping for channel {mapping.source_channel_id} already exists "
                        f"({existing.name or existing.id[:8]})."
                    )
            self._mappings[mapping.id] = mapping
            try:
                self.save()
            except OSError:
                # Roll back the in-memory change if persistence failed.
                self._mappings.pop(mapping.id, None)
                raise
            return mapping

    def remove(self, mapping_id: str) -> RelayMapping | None:
        with self._lock:
            removed = self._mappings.pop(mapping_id, None)
            if removed is not None:
                self.save()
            return removed
