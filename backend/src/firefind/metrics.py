"""Utilities for deriving summary metrics from FireFind analysis."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Mapping

from .model import Finding
from .service import AnalysisResult


SEVERITY_KEYS: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "cautionary",
    "low",
    "info",
)


def calculate_score(metrics: Mapping[str, int]) -> int:
    """Return a 0-100 security score based on severity metrics."""

    weights = {
        "critical": 30,
        "high": 15,
        "medium": 5,
        "cautionary": 3,
        "low": 2,
    }
    penalty = sum(int(metrics.get(level, 0)) * weight for level, weight in weights.items())
    score = max(0, 100 - penalty)
    return int(score)


def _normalise_severity_key(value: str) -> str:
    label = (value or "").strip().lower()
    if not label:
        return ""
    if label in {"informational", "information", "inform"}:
        return "info"
    return label


def _format_location_token(token: str) -> str:
    upper = token.upper()
    if upper == "FW":
        return "FW"
    if upper == "DAAS":
        return "DaaS"
    if upper in {"DMZ", "WAN"}:
        return upper
    return token.capitalize()


def _derive_location_label(source_file: str) -> str:
    if not source_file:
        return "Unknown"

    stem = Path(source_file).stem
    segment = stem
    marker = "Firewall Policy-"
    if marker in stem:
        segment = stem.split(marker, 1)[1]

    segment = segment.split(" - ", 1)[0].strip()
    if not segment:
        segment = stem

    tokens = [tok for tok in re.split(r"[-_]+", segment) if tok]
    formatted: list[str] = []
    for token in tokens:
        cleaned = re.sub(r"\d+$", "", token).strip()
        if not cleaned:
            continue
        formatted.append(_format_location_token(cleaned))
        if len(formatted) == 2:
            break

    if not formatted and tokens:
        formatted.append(_format_location_token(tokens[0]))

    if not formatted:
        return stem or "Unknown"

    return " ".join(formatted)


def metrics_from_findings(findings: Iterable[Finding]) -> Dict[str, int | Dict[str, Dict[str, int]]]:
    totals: Counter[str] = Counter()
    locations: dict[str, Counter[str]] = defaultdict(Counter)

    for finding in findings:
        severity_key = _normalise_severity_key(getattr(finding, "severity", ""))
        if not severity_key:
            continue
        location = _derive_location_label(getattr(finding, "source_file", ""))
        totals[severity_key] += 1
        locations[location][severity_key] += 1

    metrics: Dict[str, int | Dict[str, Dict[str, int]]] = {
        key: int(totals.get(key, 0)) for key in SEVERITY_KEYS
    }
    total_findings = sum(int(metrics[key]) for key in SEVERITY_KEYS)
    metrics["total"] = total_findings
    metrics["score"] = calculate_score({key: int(metrics[key]) for key in SEVERITY_KEYS})
    metrics["by_location"] = {
        location: {key: int(counts.get(key, 0)) for key in SEVERITY_KEYS}
        for location, counts in sorted(locations.items())
    }
    return metrics


def build_metrics(result: AnalysisResult) -> Dict[str, object]:
    rated_totals: Counter[str] = Counter()
    rated_locations: dict[str, Counter[str]] = defaultdict(Counter)
    unrated_locations: dict[str, int] = defaultdict(int)

    for rule in result.rules:
        rating = _normalise_severity_key(getattr(rule, "risk_rating", ""))
        location = _derive_location_label(getattr(rule, "source_file", ""))
        if rating:
            rated_totals[rating] += 1
            rated_locations[location][rating] += 1
        else:
            unrated_locations[location] += 1

    if rated_totals:
        metrics: Dict[str, object] = {
            key: int(rated_totals.get(key, 0)) for key in SEVERITY_KEYS
        }
        total_findings = sum(int(metrics[key]) for key in SEVERITY_KEYS)
        metrics["total"] = total_findings
        metrics["score"] = calculate_score({key: int(metrics[key]) for key in SEVERITY_KEYS})
        metrics["by_location"] = {
            location: {key: int(counts.get(key, 0)) for key in SEVERITY_KEYS}
            for location, counts in sorted(rated_locations.items())
        }

        unrated_total = sum(unrated_locations.values())
        if unrated_total:
            metrics["unrated_rules"] = {
                "total": int(unrated_total),
                "by_location": {
                    location: int(count)
                    for location, count in sorted(unrated_locations.items())
                    if count
                },
            }

        return metrics

    return metrics_from_findings(result.findings)


__all__ = [
    "SEVERITY_KEYS",
    "build_metrics",
    "calculate_score",
    "metrics_from_findings",
]