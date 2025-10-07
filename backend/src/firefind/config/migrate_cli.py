"""Command-line helper for migrating FireFind rules configuration files."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, MutableMapping

from ..utils import dump_yaml, load_yaml
from .loader import DEFAULT_RULES_CONFIG, merge_rules_config_data
from .migrations import ensure_rule_logic_structure


def migrate_rules_config(
    source: Path,
    *,
    destination: Path | None = None,
    create_backup: bool = True,
) -> Path:
    """Upgrade ``source`` to the latest schema and persist to ``destination``."""

    source = Path(source)
    if not source.exists():
        raise FileNotFoundError(f"Configuration file does not exist: {source}")

    original: Mapping[str, Any] = load_yaml(source)
    merged: MutableMapping[str, Any] = merge_rules_config_data(
        DEFAULT_RULES_CONFIG.to_dict(), original or {}
    )
    ensure_rule_logic_structure(merged, defaults=DEFAULT_RULES_CONFIG, original=original or {})

    target = Path(destination) if destination else source
    target.parent.mkdir(parents=True, exist_ok=True)

    if create_backup and target == source:
        backup_path = source.with_suffix(source.suffix + ".bak")
        shutil.copy2(source, backup_path)

    dump_yaml(target, merged)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize a FireFind rules configuration file so it includes the "
            "structured rule logic, risk thresholds, and supporting metadata "
            "expected by the latest releases."
        )
    )
    parser.add_argument(
        "source",
        type=Path,
        help="Path to the existing rules configuration YAML file.",
    )
    parser.add_argument(
        "--output",
        dest="output",
        type=Path,
        default=None,
        help=(
            "Optional destination path. When omitted the source file is "
            "updated in place."
        ),
    )
    parser.add_argument(
        "--no-backup",
        dest="create_backup",
        action="store_false",
        help=(
            "Disable creation of a .bak backup when writing in-place. Backups "
            "are enabled by default."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        target = migrate_rules_config(
            args.source,
            destination=args.output,
            create_backup=args.create_backup,
        )
    except FileNotFoundError as error:
        parser.error(str(error))
        return 2
    except Exception as error:  # pragma: no cover - defensive error surface
        message = json.dumps({"error": str(error)}, ensure_ascii=False)
        sys.stderr.write(f"{message}\n")
        return 1

    sys.stdout.write(f"Configuration migrated successfully → {target}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
