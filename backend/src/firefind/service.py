from __future__ import annotations

"""Core analysis service for FireFind."""

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Set, Tuple, TypedDict
import os
import logging

from .loaders.csv_xlsx_loader import load_table
from .model import Rule, Finding
from .rules_engine import run_checks, generate_risk_code
from .config import load_rules_config, RulesConfig
from .utils import (
    RuleValidationError,
    RuleValidationIssue,
    load_yaml,
    merge_tags,
    pick_mapping,
    to_rule,
)


logger = logging.getLogger(__name__)

_ADMIN_PORT_DEDUP_MODES = {"per_port", "per_group", "all_groups"}

ADMIN_PORT_DEDUPLICATION_MODE = (
    os.environ.get("FIREFIND_ADMIN_PORT_DEDUP_MODE", "all_groups").strip().lower()
)
if ADMIN_PORT_DEDUPLICATION_MODE not in _ADMIN_PORT_DEDUP_MODES:
    logger.warning(
        "Unknown admin port deduplication mode: %s. Falling back to all_groups.",
        ADMIN_PORT_DEDUPLICATION_MODE,
    )
    ADMIN_PORT_DEDUPLICATION_MODE = "all_groups"


@dataclass
class AnalysisResult:
    findings: List[Finding]
    rules: List[Rule]
    rejections: List["RuleRejection"] = field(default_factory=list)


@dataclass
class RuleRejection:
    row: Mapping[str, object]
    issues: Tuple[RuleValidationIssue, ...]

_SEVERITY_PRIORITY: Dict[str, int] = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Cautionary": 2,
    "Low": 1,
    "Info": 0,
}


def _severity_rank(severity: str) -> int:
    """Return a numeric priority for a severity label."""

    return _SEVERITY_PRIORITY.get(severity or "", -1)


def _resequence_risk_codes(findings: List[Finding]) -> None:
    """Ensure risk codes are sequential after de-duplication."""

    counters: Dict[str, int] = {}

    for finding in findings:
        if finding.finding_type != "admin_port_exposed":
            finding.risk_code = finding.risk_code or ""
            continue

        counter = counters.get(finding.finding_type, 0) + 1
        counters[finding.finding_type] = counter
        finding.risk_code = generate_risk_code(
            finding.finding_type, finding.severity, counter
        )


class _GroupedEntry(TypedDict):
    primary: Finding
    details: List[Finding]
    ports: Set[str]
    groups: Set[str]
    rules: Set[str]


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """De-duplicate findings keeping the highest severity entry for each key."""

    grouped: Dict[Tuple[str, ...], _GroupedEntry] = {}
    ordered_keys: List[Tuple[str, ...]] = []

    def _port_literal(finding: Finding) -> str:
        port_text = finding.port or ""
        if "/" in port_text:
            return port_text
        proto_text = (finding.proto or "").upper()
        if proto_text and port_text:
            return f"{proto_text}/{port_text}"
        if proto_text:
            return proto_text
        return port_text

    for finding in findings:
        port_profile = getattr(finding, "port_profile", "")
        mode = ADMIN_PORT_DEDUPLICATION_MODE

        if finding.finding_type == "admin_port_exposed":
            if mode == "all_groups":
                key_fields = (
                    finding.vendor,
                    finding.src,
                    finding.dst,
                    finding.proto,
                    finding.action,
                    finding.finding_type,
                    finding.source_file,
                )
            elif mode == "per_group":
                group_component = port_profile or finding.port
                key_fields = (
                    finding.vendor,
                    finding.rule_id,
                    finding.src,
                    finding.dst,
                    finding.proto,
                    group_component,
                    finding.action,
                    finding.finding_type,
                    finding.rationale,
                    finding.source_file,
                )
            else:  # per_port
                key_fields = (
                    finding.vendor,
                    finding.rule_id,
                    finding.src,
                    finding.dst,
                    finding.proto,
                    finding.port,
                    finding.action,
                    finding.finding_type,
                    finding.rationale,
                    finding.source_file,
                )
        else:
            port_group = port_profile or finding.port
            key_fields = (
                finding.vendor,
                finding.rule_id,
                finding.src,
                finding.dst,
                finding.proto,
                port_group,
                finding.action,
                finding.finding_type,
                finding.rationale,
                finding.source_file,
            )

        entry = grouped.get(key_fields)
        if entry is None:
            entry = {
                "primary": finding,
                "details": [],
                "ports": set(),
                "groups": set(),
                "rules": set(),
            }
            grouped[key_fields] = entry
            ordered_keys.append(key_fields)

        entry["details"].append(finding)

        if finding.finding_type == "admin_port_exposed":
            entry["ports"].add(_port_literal(finding))
            if port_profile:
                entry["groups"].add(port_profile)
            if finding.rule_id:
                entry["rules"].add(finding.rule_id)

        primary = entry["primary"]

        primary_rank = _severity_rank(primary.severity)
        finding_rank = _severity_rank(finding.severity)

        if finding_rank > primary_rank:
            entry["primary"] = finding
            continue

        if (
            finding_rank == primary_rank
            and primary.finding_type != "admin_port_exposed"
            and finding.finding_type == "admin_port_exposed"
        ):
            entry["primary"] = finding

    findings_unique: List[Finding] = []

    for key in ordered_keys:
        entry = grouped[key]
        primary = entry["primary"]

        rationale_parts: List[str] = []
        seen_pairs = set()
        contributing_severities: List[str] = []
        details = entry["details"]
        for detail in details:
            assert isinstance(detail, Finding)
            pair = (detail.finding_type, detail.rationale)
            contributing_severities.append(detail.severity)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if detail is primary:
                continue
            label = detail.finding_type.replace("_", " ")
            rationale_parts.append(f"{label}: {detail.rationale}")

        combined_rationale = primary.rationale
        if rationale_parts:
            combined_rationale = (
                f"{combined_rationale} | Additional issues: "
                + " | ".join(rationale_parts)
            )

        additional_tag_sources = [detail.tags for detail in details if detail is not primary]
        combined_tags = merge_tags(primary.tags, *additional_tag_sources)

        rule_id = primary.rule_id
        port_value = primary.port
        port_profile_value = getattr(primary, "port_profile", "")
        label_value = getattr(primary, "label", "")

        if (
            primary.finding_type == "admin_port_exposed"
            and ADMIN_PORT_DEDUPLICATION_MODE == "all_groups"
        ):
            contributing_groups = sorted(entry["groups"], key=lambda value: value.lower())
            contributing_ports = sorted(entry["ports"], key=lambda value: value.lower())
            groups_text = ", ".join(contributing_groups)
            ports_text = ", ".join(contributing_ports)
            if groups_text and ports_text:
                port_value = f"{groups_text} ({ports_text})"
            elif groups_text:
                port_value = groups_text
            elif ports_text:
                port_value = ports_text

            if contributing_groups or len(contributing_ports) > 1:
                port_profile_value = "combined"

            contributing_rules = sorted(entry["rules"])
            if len(contributing_rules) > 1:
                rule_id = "admin_ports_combined"
                label_value = "Administrative ports exposed (combined)"
                extra_rules = [rid for rid in contributing_rules if rid != primary.rule_id]
                if extra_rules:
                    combined_rationale = (
                        f"{combined_rationale} | +{len(extra_rules)} other matching rules: "
                        + ", ".join(extra_rules)
                    )

        deduped_finding = Finding(
            vendor=primary.vendor,
            rule_id=rule_id,
            src=primary.src,
            dst=primary.dst,
            proto=primary.proto,
            port=port_value,
            port_profile=port_profile_value,
            action=primary.action,
            finding_type=primary.finding_type,
            severity=primary.severity,
            rationale=combined_rationale,
            risk_code=primary.risk_code,
            source_file=primary.source_file,
            contributing_severities=tuple(contributing_severities),
            risk_rating="",
            tags=combined_tags,
            hit_count=primary.hit_count,
            byte_count=primary.byte_count,
            rule_enabled=primary.rule_enabled,
        )

        if label_value:
            setattr(deduped_finding, "label", label_value)

        findings_unique.append(deduped_finding)

    _resequence_risk_codes(findings_unique)

    return findings_unique


def _resolve_config_path(path: Path) -> Path:
    if path.exists():
        return path
    if path.is_absolute():
        return path
    base = Path(__file__).resolve().parents[2]
    candidate = base / path
    return candidate if candidate.exists() else path


def _collect_rules(
    input_path: Path,
    vendor: str,
    rules_path: Path,
    mappings_path: Path,
) -> Tuple[List[Rule], RulesConfig, List[RuleRejection]]:
    rules_path = _resolve_config_path(Path(rules_path))
    mappings_path = _resolve_config_path(Path(mappings_path))

    rules_cfg = load_rules_config(rules_path)
    vendor_mappings = load_yaml(mappings_path)
    mapping = pick_mapping(vendor_mappings, vendor)

    raw_rows = []
    if input_path.is_dir():
        files = list(sorted(input_path.glob("*.csv"))) + list(
            sorted(input_path.glob("*.xlsx"))
        )
        for f in files:
            for row in load_table(f):
                row["_source_file"] = f.name
                raw_rows.append(row)
    else:
        for row in load_table(input_path):
            row["_source_file"] = input_path.name
            raw_rows.append(row)

    rules_norm: List[Rule] = []
    rejections: List[RuleRejection] = []
    seen_rules = set()
    for row in raw_rows:
        try:
            rule = to_rule(row, mapping, vendor=vendor, config=rules_cfg)
        except RuleValidationError as exc:
            rejection_row: Mapping[str, object] = (
                exc.row if exc.row is not None else row
            )
            rejections.append(
                RuleRejection(
                    row=dict(rejection_row),
                    issues=exc.issues,
                )
            )
            continue
        if not rule:
            continue
        key = (rule.rule_id, rule.src, rule.dst, rule.proto, rule.port, rule.action)
        if key in seen_rules:
            continue
        seen_rules.add(key)
        rules_norm.append(rule)

    if rejections:
        counts = Counter(
            issue.code for rejection in rejections for issue in rejection.issues
        )
        summary = ", ".join(
            f"{code}={count}" for code, count in sorted(counts.items())
        )
        logger.warning(
            "Rejected %d row(s) due to validation errors: %s",
            len(rejections),
            summary,
        )

    return rules_norm, rules_cfg, rejections


def run_analysis(
    input_path: Path,
    vendor: str = "generic",
    rules_path: Path = Path("rules/rules.yaml"),
    mappings_path: Path = Path("rules/vendor_mappings.yaml"),
) -> AnalysisResult:
    input_path = Path(input_path)
    rules, rules_cfg, rejections = _collect_rules(
        input_path, vendor, rules_path, mappings_path
    )
    findings = run_checks(vendor, rules, rules_cfg)
    unique = deduplicate_findings(findings)
    return AnalysisResult(findings=unique, rules=rules, rejections=rejections)
