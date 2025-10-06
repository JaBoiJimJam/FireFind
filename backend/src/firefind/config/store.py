"""Persistence utilities for managing the runtime rules configuration."""
from __future__ import annotations

import json
import os
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

from ..utils import dump_yaml, load_yaml
from .loader import DEFAULT_RULES_CONFIG, load_rules_config, merge_rules_config_data
from .schema import RulesConfig


@dataclass
class RevisionSummary:
    """Metadata describing a configuration revision."""

    version: int
    timestamp: str
    actor: str
    summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "summary": self.summary,
        }


class RulesConfigStore:
    """Simple file-backed store for the FireFind rules configuration."""

    def __init__(
        self,
        config_path: Path | None = None,
        history_path: Path | None = None,
    ) -> None:
        base_dir = Path(__file__).resolve().parents[2]
        default_config_path = base_dir / "rules" / "rules.yaml"
        config_env = os.getenv("FIRE_FIND_RULES_CONFIG")
        history_env = os.getenv("FIRE_FIND_RULES_HISTORY")

        self.config_path = Path(config_path or config_env or default_config_path)
        default_history = self.config_path.with_name(
            f"{self.config_path.stem}.history.jsonl"
        )
        self.history_path = Path(history_path or history_env or default_history)

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def load_active(self) -> RulesConfig:
        """Return the merged runtime configuration."""

        return load_rules_config(self.config_path)

    def load_raw(self) -> MutableMapping[str, Any]:
        """Return the user-provided overrides without defaults applied."""

        if not self.config_path.exists():
            return {}
        return load_yaml(self.config_path)

    # ------------------------------------------------------------------
    # History helpers
    # ------------------------------------------------------------------

    def _iter_history(self) -> Iterable[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        with self.history_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield record

    def get_history(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return revision records ordered from oldest to newest."""

        if limit is None or limit <= 0:
            return list(self._iter_history())

        window: deque[dict[str, Any]] = deque(maxlen=limit)
        for record in self._iter_history():
            window.append(record)
        return list(window)

    def latest_revision(self) -> RevisionSummary | None:
        """Return metadata for the most recent revision."""

        history = self.get_history(limit=1)
        if not history:
            return None
        record = history[-1]
        return RevisionSummary(
            version=int(record.get("version", 0)),
            timestamp=str(record.get("timestamp", "")),
            actor=str(record.get("actor", "")),
            summary=record.get("summary"),
        )

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def update(
        self,
        patch: Mapping[str, Any],
        *,
        actor: str,
        summary: str | None = None,
    ) -> tuple[RulesConfig, RevisionSummary]:
        """Apply ``patch`` to the stored configuration and record a revision."""

        if not patch:
            raise ValueError("No configuration changes supplied")

        current_raw = self.load_raw()
        updated_raw = merge_rules_config_data(current_raw, patch)

        if updated_raw == current_raw:
            raise ValueError("No configuration changes detected")

        merged_for_validation = merge_rules_config_data(
            DEFAULT_RULES_CONFIG.to_dict(), updated_raw
        )
        config = RulesConfig.from_dict(merged_for_validation)

        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        dump_yaml(self.config_path, updated_raw)

        # Persist revision record
        last_revision = self.latest_revision()
        next_version = 1 if not last_revision else last_revision.version + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "version": next_version,
            "timestamp": timestamp,
            "actor": actor,
            "summary": summary,
            "changes": patch,
            "config": config.to_dict(),
        }
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=False))
            handle.write("\n")

        revision = RevisionSummary(
            version=next_version,
            timestamp=timestamp,
            actor=actor,
            summary=summary,
        )
        return config, revision


__all__ = ["RulesConfigStore", "RevisionSummary"]