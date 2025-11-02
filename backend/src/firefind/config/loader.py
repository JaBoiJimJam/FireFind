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
        21,
        22,
        23,
        25,
        53,
        80,
        88,
        123,
        135,
        137,
        138,
        139,
        389,
        443,
        445,
        464,
        514,
        515,
        587,
        636,
        1024,
        1025,
        1026,
        1433,
        3268,
        3269,
        3389,
        27000,
        7279,
        8810,
        8811,
        49152,
        65435,
        65535,
    ],
    "critical_risk_admin_ports": [
        21,
        135,
        137,
        138,
        139,
        514,
        1024,
        1025,
        1026,
        27000,
        7279,
        49152,
        65435,
        65535,
    ],
    "high_risk_admin_ports": [22, 23, 3389, 515, 8810, 8811],
    "medium_risk_admin_ports": [445],
    "low_risk_admin_ports": [25, 587],
    "admin_port_signatures": {
        "Critical": [
            {"ports": [21], "services": ["ftp"]},
            {"ports": [21, 22, 80, 443], "services": ["ftp", "http", "https", "ssh"]},
            {"ports": [1025, 1026, 49152, 65435], "services": ["adports", "echo-reply", "echo-request", "remote_storm", "tcp-49152_65435", "tcp_1026"]},
            {"ports": [1025, 1026, 49152, 65435, 65535], "services": ["adports", "echo-reply", "echo-request", "remote_storm", "tcp-49152_65535", "tcp_1026"]},
            {"ports": [135, 445], "services": ["microsoft-ds", "nbt_", "tcp_135"]},
            {"ports": [135, 1024, 1025, 1026, 1433, 3268, 3269, 3389, 7279, 8810, 8811, 27000, 49152, 65435, 65535], "services": ["tcp-high-ports", "tcp_135", "tcp_27000", "tcp_7279"]},
            {"ports": [464, 1024, 1025, 1026, 1433, 3268, 3269, 3389, 7279, 8810, 8811, 27000, 49152, 65435, 65535], "services": ["adports", "tcp-high-ports", "tcp_464"]},
            {"ports": [514], "services": ["shell", "syslog"]},
        ],
        "High": [
            {"ports": [22], "services": ["ssh"]},
            {"ports": [22, 23], "services": ["ssh", "ssh_version_2", "telnet"]},
            {"ports": [22, 8810, 8811], "services": ["ssh", "tcp_8810-8811"]},
            {"ports": [3389], "services": ["rdp"]},
            {"ports": [515], "services": ["lpdw0rm"]},
        ],
        "Medium": [
            {"ports": [445], "services": ["microsoft-ds"]}
        ],
        "Low": [
            {"ports": [25], "services": ["smtp"]}
        ],
        "Cautionary": [
            {"ports": [53, 636], "services": ["domain-udp_", "ldap-ssl"]},
            {"ports": [80], "services": ["http"]},
            {"ports": [80, 1433], "services": ["http", "ms-sql-server"]},
            {"ports": [80, 443], "services": ["http", "https"]},
            {"ports": [80, 443, 1433], "services": ["http", "https", "ms-sql-server"]},
            {"ports": [389, 464, 3268], "services": ["dns_", "kerberos_", "ldap", "ntp", "tcp_3268", "tcp_464", "udp_464"]},
        ],
    },
    "broad_cidr_prefix_max": 8,
    "rule_overlap": {
        "max_rules_evaluated": 500,
        "max_rule_pairs": 5000,
        "redundant_severity": Severity.LOW.value,
        "shadowed_severity": Severity.MEDIUM.value,
    },
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
        "cautionary": {
            "label": "Cautionary Risk",
            "severity": Severity.CAUTIONARY.value,
            "thresholds": {"min_score": 25},
            "rationale": {
                "summary": "Emerging exposure that warrants monitoring and scheduled remediation.",
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
            "directions": {
                "outbound": {
                    "max_prefix": 12,
                    "description": "Outbound rules can be slightly broader without immediate escalation.",
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