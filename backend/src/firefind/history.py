"""Persistence helpers for scan history and trend aggregation."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

from .metrics import SEVERITY_KEYS


_SQLITE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}


def _default_history_path() -> Path:
    base_dir = Path(__file__).resolve().parents[2]
    return base_dir / "data" / "scan_history.jsonl"


def _ensure_timestamp(timestamp: datetime | None) -> str:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.isoformat()
    raise TypeError("timestamp must be a datetime instance or None")


def _prepare_metrics(metrics: Mapping[str, Any]) -> MutableMapping[str, Any]:
    prepared: MutableMapping[str, Any] = {}
    for key, value in metrics.items():
        if isinstance(value, dict):
            prepared[key] = json.loads(json.dumps(value))
        else:
            prepared[key] = value
    return prepared


@dataclass(slots=True)
class ScanRecord:
    """Structured representation of a persisted scan summary."""

    timestamp: str
    vendor: str
    metrics: MutableMapping[str, Any]
    metadata: MutableMapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "vendor": self.vendor,
            "metrics": self.metrics,
        }
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


class ScanHistoryStore:
    """Append-only store tracking scan summaries for trend analysis."""

    def __init__(self, path: Path | None = None) -> None:
        env_path = os.getenv("FIRE_FIND_SCAN_HISTORY")
        resolved = Path(path or env_path or _default_history_path())
        self.path = resolved
        self.backend = "sqlite" if resolved.suffix.lower() in _SQLITE_EXTENSIONS else "jsonl"
        if self.backend == "sqlite":
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialise_sqlite()

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def record_scan(
        self,
        vendor: str,
        metrics: Mapping[str, Any],
        *,
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ScanRecord:
        """Persist ``metrics`` for ``vendor`` and return the stored record."""

        payload = ScanRecord(
            timestamp=_ensure_timestamp(timestamp),
            vendor=vendor or "unknown",
            metrics=_prepare_metrics(dict(metrics)),
            metadata=dict(metadata) if metadata else None,
        )
        if self.backend == "sqlite":
            self._append_sqlite(payload)
        else:
            self._append_jsonl(payload)
        return payload

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_history(
        self,
        limit: int | None = None,
        vendor: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return stored records ordered from oldest to newest."""

        records = list(self._iter_records(vendor=vendor))
        if limit is None or limit <= 0 or limit >= len(records):
            return [record.to_dict() for record in records]
        return [record.to_dict() for record in records[-limit:]]

    def _iter_records(
        self,
        *,
        vendor: str | None = None,
    ) -> Iterable[ScanRecord]:
        if self.backend == "sqlite":
            yield from self._iter_sqlite(vendor=vendor)
        else:
            yield from self._iter_jsonl(vendor=vendor)

    # ------------------------------------------------------------------
    # JSONL backend
    # ------------------------------------------------------------------

    def _append_jsonl(self, record: ScanRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), sort_keys=False))
            handle.write("\n")

    def _iter_jsonl(self, *, vendor: str | None) -> Iterable[ScanRecord]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if vendor and payload.get("vendor") != vendor:
                    continue
                metrics = payload.get("metrics") or {}
                metadata = payload.get("metadata")
                yield ScanRecord(
                    timestamp=str(payload.get("timestamp", "")),
                    vendor=str(payload.get("vendor", "")),
                    metrics=dict(metrics),
                    metadata=dict(metadata) if isinstance(metadata, dict) else None,
                )

    # ------------------------------------------------------------------
    # SQLite backend
    # ------------------------------------------------------------------

    def _initialise_sqlite(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    metrics TEXT NOT NULL,
                    metadata TEXT
                )
                """
            )

    def _append_sqlite(self, record: ScanRecord) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                INSERT INTO scan_history (timestamp, vendor, metrics, metadata)
                VALUES (?, ?, ?, ?)
                """,
                (
                    record.timestamp,
                    record.vendor,
                    json.dumps(record.metrics, sort_keys=False),
                    json.dumps(record.metadata, sort_keys=False)
                    if record.metadata
                    else None,
                ),
            )

    def _iter_sqlite(self, *, vendor: str | None) -> Iterable[ScanRecord]:
        if not self.path.exists():
            return []
        query = "SELECT timestamp, vendor, metrics, metadata FROM scan_history"
        params: list[Any] = []
        if vendor:
            query += " WHERE vendor = ?"
            params.append(vendor)
        query += " ORDER BY timestamp ASC, id ASC"
        with sqlite3.connect(self.path) as connection:
            cursor = connection.execute(query, params)
            for ts, vend, metrics_json, metadata_json in cursor.fetchall():
                metrics = json.loads(metrics_json or "{}")
                metadata = json.loads(metadata_json) if metadata_json else None
                yield ScanRecord(
                    timestamp=str(ts),
                    vendor=str(vend),
                    metrics=dict(metrics),
                    metadata=dict(metadata) if isinstance(metadata, dict) else None,
                )


def compute_trends(
    records: Sequence[Mapping[str, Any]],
    *,
    window: int = 5,
) -> dict[str, Any]:
    """Return aggregate statistics for ``records``."""

    total_runs = len(records)
    if total_runs == 0:
        return {
            "total_runs": 0,
            "window_size": 0,
            "latest": None,
            "rolling_averages": {
                "score": 0.0,
                "total": 0.0,
                "severity": {key: 0.0 for key in SEVERITY_KEYS},
            },
            "score_delta": 0.0,
            "total_delta": 0.0,
            "vendors": {},
        }

    window = max(1, window)
    window_records = list(records[-window:])

    def _mean(values: Sequence[float]) -> float:
        return round(sum(values) / len(values), 2) if values else 0.0

    def _metric(record: Mapping[str, Any], key: str) -> float:
        metrics = record.get("metrics") or {}
        value = metrics.get(key, 0)
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    rolling = {
        "score": _mean([_metric(record, "score") for record in window_records]),
        "total": _mean([_metric(record, "total") for record in window_records]),
        "severity": {
            key: _mean([
                _metric(record, key) for record in window_records
            ])
            for key in SEVERITY_KEYS
        },
    }

    latest = records[-1]
    prev = records[-2] if total_runs >= 2 else None
    score_delta = _metric(latest, "score") - (_metric(prev, "score") if prev else 0.0)
    total_delta = _metric(latest, "total") - (_metric(prev, "total") if prev else 0.0)

    vendor_stats: dict[str, dict[str, Any]] = {}
    for record in records:
        vendor = str(record.get("vendor", "unknown")) or "unknown"
        score = _metric(record, "score")
        vendor_entry = vendor_stats.setdefault(
            vendor,
            {
                "runs": 0,
                "average_score": 0.0,
                "last_score": score,
                "last_seen": record.get("timestamp"),
            },
        )
        vendor_entry["runs"] += 1
        vendor_entry.setdefault("_scores", []).append(score)
        vendor_entry["last_score"] = score
        vendor_entry["last_seen"] = record.get("timestamp")

    for vendor, entry in vendor_stats.items():
        scores = entry.pop("_scores", [])
        entry["average_score"] = _mean(scores)

    return {
        "total_runs": total_runs,
        "window_size": len(window_records),
        "latest": latest,
        "rolling_averages": rolling,
        "score_delta": round(score_delta, 2),
        "total_delta": round(total_delta, 2),
        "vendors": vendor_stats,
    }


__all__ = ["ScanHistoryStore", "ScanRecord", "compute_trends"]