"""Utilities for loading and merging FireFind rule configurations."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, MutableMapping

from ..utils import load_yaml
from .migrations import ensure_rule_logic_structure
from .schema import RulesConfig, Severity


DEFAULT_RULES_CONFIG_DATA: MutableMapping[str, Any] = {
    "admin_ports": [
        2,
        3,
        4,
        5,
        8,
        12,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        137,
        138,
        139,
        143,
        161,
        389,
        443,
        445,
        464,
        465,
        514,
        515,
        636,
        993,
        995,
        1024,
        1025,
        1026,
        1080,
        1433,
        1434,
        1521,
        1723,
        1900,
        2049,
        2082,
        2083,
        2303,
        3074,
        3128,
        3268,
        3269,
        3306,
        3389,
        4000,
        4444,
        5000,
        5060,
        5432,
        5555,
        5900,
        5939,
        5985,
        5986,
        6379,
        6667,
        6697,
        7279,
        8000,
        8080,
        8081,
        8443,
        8810,
        8811,
        8888,
        9090,
        9100,
        9200,
        10000,
        27000,
        27017,
        28017,
        49152,
        65435,
        65535,
    ],
    "critical_risk_admin_ports": [
        4,
        5,
        8,
        12,
        21,
        22,
        80,
        135,
        443,
        445,
        464,
        514,
        1024,
        1025,
        1026,
        3268,
        3269,
        7279,
        27000,
        49152,
        65435,
        65535,
    ],
    "high_risk_admin_ports": [23, 3389, 515, 5900, 5985, 5986, 8810, 8811],
    "medium_risk_admin_ports": [
        2,
        3,
        53,
        110,
        111,
        137,
        138,
        139,
        143,
        161,
        389,
        465,
        636,
        993,
        995,
        1080,
        1433,
        1434,
        1521,
        1723,
        1900,
        2049,
        2082,
        2083,
        2303,
        3074,
        3128,
        3306,
        4000,
        4444,
        5000,
        5060,
        5432,
        5555,
        5939,
        6379,
        6667,
        6697,
        8000,
        8080,
        8081,
        8443,
        8888,
        9090,
        9100,
        9200,
        10000,
        27017,
        28017,
    ],
    "low_risk_admin_ports": [25],
    "broad_cidr_prefix_max": 8,
    "risk_levels": {
        "critical": {
            "label": "Critical Risk",
            "severity": Severity.CRITICAL.value,
            "thresholds": {"min_score": 90, "min_findings": 1},
            "rationale": {
                "summary": "Exposure that allows immediate compromise of sensitive assets.",
                "details": "These findings require emergency response and executive visibility.",
                "references": [
                    "NIST SP 800-30 Rev.1",
                    "MITRE ATT&CK Initial Access",
                ],
            },
        },
        "high": {
            "label": "High Risk",
            "severity": Severity.HIGH.value,
            "thresholds": {"min_score": 70, "min_findings": 1},
            "rationale": {
                "summary": "Significant exposure with high likelihood of exploitation.",
                "details": "Remediation should be prioritized within the next change cycle.",
                "references": ["CIS CSC v8 IG1"],
            },
        },
        "medium": {
            "label": "Medium Risk",
            "severity": Severity.MEDIUM.value,
            "thresholds": {"min_score": 40},
            "rationale": {
                "summary": "Exposure that should be remediated but does not pose an immediate threat.",
                "references": ["NIST CSF PR.AC"],
            },
        },
        "low": {
            "label": "Low Risk",
            "severity": Severity.LOW.value,
            "thresholds": {"min_score": 0},
            "rationale": {
                "summary": "Informational conditions or minor hygiene opportunities.",
            },
        },
    },
    "cidr_limits": {
        "broad_networks": {
            "default": {
                "max_prefix": 8,
                "blocked": ["0.0.0.0/0", "::/0"],
                "description": "Networks broader than /8 are escalated as risky.",
            },
            "analyzers": {
                "admin_port_exposed": {
                    "max_prefix": 12,
                    "description": "Admin port analyzer is slightly more permissive to avoid noise.",
                }
            },
            "vendors": {
                "fortinet": {"max_prefix": 10},
            },
            "directions": {
                "outbound": {
                    "max_prefix": 12,
                    "description": "Outbound rules can be slightly broader without immediate escalation.",
                }
            },
            "vendor_direction_overrides": {
                "fortinet": {
                    "inbound": {
                        "max_prefix": 9,
                        "description": "Inbound Fortinet policies are held to stricter network boundaries.",
                    }
                }
            },
        }
    },
    "port_groups": {
        "core_admin": {
            "description": "Common administrative protocols requiring strict control.",
            "protocol": "tcp",
            "ranges": [
                "22",
                "80",
                "443",
                "3389",
                "5900",
            ],
        },
        "directory_services": {
            "description": "Directory-related services",
            "protocol": "tcp",
            "ranges": [
                "389",
                "636",
            ],
        },
        "legacy_management": {
            "description": "Legacy and insecure remote management ports",
            "protocol": "tcp",
            "ranges": ["23", "515", "1024-1026", "2303", "27000"],
        },
    },
}

DEFAULT_RULES_CONFIG_DATA["rules"] = {
    "admin_port_exposed": {
        "id": "admin_port_exposed",
        "label": "Administrative Port Exposure",
        "description": "Flags allow rules that expose administrative services to untrusted networks.",
        "conditions": {
            "logic": "all",
            "conditions": [
                {"field": "action", "comparator": "equals", "value": "allow"},
            ],
            "groups": [
                {
                    "logic": "any",
                    "conditions": [
                        {
                            "field": "service",
                            "comparator": "matches_port_group",
                            "values": [
                                "core_admin",
                                "directory_services",
                                "legacy_management",
                            ],
                        },
                        {"field": "port", "comparator": "matches_admin_port"},
                    ],
                }
            ],
        },
        "analyzers": {
            "admin_port_exposed": {
                "enabled": True,
                "notes": "Derives severity tiers from configured administrative port sets.",
                "severity_overrides": {
                    "critical": Severity.CRITICAL.value,
                    "high": Severity.HIGH.value,
                    "medium": Severity.MEDIUM.value,
                    "low": Severity.LOW.value,
                },
                "admin_ports": {
                    "baseline": list(DEFAULT_RULES_CONFIG_DATA["admin_ports"]),
                    "per_risk_overrides": {
                        "critical": list(DEFAULT_RULES_CONFIG_DATA["critical_risk_admin_ports"]),
                        "high": list(DEFAULT_RULES_CONFIG_DATA["high_risk_admin_ports"]),
                        "medium": list(DEFAULT_RULES_CONFIG_DATA["medium_risk_admin_ports"]),
                        "low": list(DEFAULT_RULES_CONFIG_DATA["low_risk_admin_ports"]),
                    },
                },
            }
        },
    }
}


DEFAULT_RULES_CONFIG = RulesConfig.from_dict(DEFAULT_RULES_CONFIG_DATA)


def _deep_merge(base: MutableMapping[str, Any], override: Mapping[str, Any]) -> MutableMapping[str, Any]:
    """Recursively merge ``override`` into ``base`` returning a copy."""

    result: MutableMapping[str, Any] = deepcopy(base)
    for key, value in (override or {}).items():
        if key in result and isinstance(result[key], Mapping) and isinstance(value, Mapping):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def merge_rules_config_data(
    base: Mapping[str, Any], override: Mapping[str, Any]
) -> MutableMapping[str, Any]:
    """Return ``base`` updated with ``override`` using the deep merge semantics."""

    return _deep_merge(dict(base), override)


def load_rules_config(
    path: Path,
    *,
    defaults: RulesConfig = DEFAULT_RULES_CONFIG,
) -> RulesConfig:
    """Load a rules configuration file and merge it with defaults."""

    user_data = load_yaml(Path(path)) if path else {}
    merged_dict = _deep_merge(defaults.to_dict(), user_data or {})
    ensure_rule_logic_structure(merged_dict, defaults=defaults, original=user_data or {})
    return RulesConfig.from_dict(merged_dict)