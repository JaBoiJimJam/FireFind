from __future__ import annotations

from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BACKEND_DIR / "src"))

from firefind.history import ScanHistoryStore, compute_trends  # noqa: E402


def test_history_store_jsonl_roundtrip(tmp_path: Path) -> None:
    history_path = tmp_path / "history.jsonl"
    store = ScanHistoryStore(path=history_path)

    first = store.record_scan(
        vendor="generic",
        metrics={
            "critical": 0,
            "high": 1,
            "medium": 0,
            "cautionary": 0,
            "low": 0,
            "info": 0,
            "total": 1,
            "score": 90,
        },
    )
    store.record_scan(
        vendor="vendor-b",
        metrics={
            "critical": 1,
            "high": 0,
            "medium": 0,
            "cautionary": 0,
            "low": 0,
            "info": 0,
            "total": 1,
            "score": 70,
        },
    )

    history = store.get_history()
    assert len(history) == 2
    assert history[0]["timestamp"] == first.timestamp
    assert history[1]["vendor"] == "vendor-b"

    latest_only = store.get_history(limit=1)
    assert len(latest_only) == 1
    assert latest_only[0]["vendor"] == "vendor-b"


def test_history_store_sqlite(tmp_path: Path) -> None:
    db_path = tmp_path / "history.sqlite"
    store = ScanHistoryStore(path=db_path)

    store.record_scan(
        vendor="generic",
        metrics={
            "critical": 0,
            "high": 0,
            "medium": 1,
            "cautionary": 0,
            "low": 0,
            "info": 0,
            "total": 1,
            "score": 95,
        },
    )

    history = store.get_history()
    assert len(history) == 1
    assert history[0]["vendor"] == "generic"


def test_compute_trends_multiple_records() -> None:
    records = [
        {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "vendor": "generic",
            "metrics": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "cautionary": 0,
                "low": 0,
                "info": 0,
                "total": 1,
                "score": 95,
            },
        },
        {
            "timestamp": "2024-01-02T00:00:00+00:00",
            "vendor": "generic",
            "metrics": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "cautionary": 0,
                "low": 0,
                "info": 0,
                "total": 1,
                "score": 65,
            },
        },
        {
            "timestamp": "2024-01-03T00:00:00+00:00",
            "vendor": "vendor-b",
            "metrics": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "cautionary": 0,
                "low": 0,
                "info": 0,
                "total": 1,
                "score": 85,
            },
        },
    ]

    trends = compute_trends(records, window=2)
    assert trends["total_runs"] == 3
    assert trends["window_size"] == 2
    assert trends["rolling_averages"]["score"] == 75.0
    assert trends["score_delta"] == 20.0
    assert trends["vendors"]["generic"]["runs"] == 2


def test_compute_trends_empty() -> None:
    trends = compute_trends([], window=5)
    assert trends["total_runs"] == 0
    assert trends["rolling_averages"]["score"] == 0.0