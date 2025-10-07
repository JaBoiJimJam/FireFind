"""Vendor normalisation entry points."""

from __future__ import annotations

from typing import Callable, Dict

from .barracuda import normalize_row as normalize_barracuda
from .checkpoint import normalize_row as normalize_checkpoint
from .fortinet import normalize_row as normalize_fortinet
from .sophos import normalize_row as normalize_sophos
from .watchguard import normalize_row as normalize_watchguard

Row = Dict[str, str]
Mapping = Dict[str, list]

_NORMALIZERS: Dict[str, Callable[[Row, Mapping], Row]] = {
    "fortinet": normalize_fortinet,
    "sophos": normalize_sophos,
    "barracuda": normalize_barracuda,
    "check point": normalize_checkpoint,
    "checkpoint": normalize_checkpoint,
    "watchguard": normalize_watchguard,
    "watch guard": normalize_watchguard,
}


def apply_vendor_normalizer(vendor: str, row: Row, mapping: Mapping) -> Row:
    """Return a vendor-aware copy of ``row`` ready for ``to_rule``."""

    key = (vendor or "").strip().lower()
    normalizer = _NORMALIZERS.get(key)
    if not normalizer:
        return dict(row)
    return normalizer(row, mapping)
