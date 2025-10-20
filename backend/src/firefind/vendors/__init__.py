"""Vendor normalisation entry points."""

from __future__ import annotations

from typing import Callable, Dict

Row = Dict[str, str]
Mapping = Dict[str, list]

# Repository no longer ships vendor-specific normalisers.  The dictionary is kept
# so third parties can register custom handlers at runtime if desired.
_NORMALIZERS: Dict[str, Callable[[Row, Mapping], Row]] = {}


def register_normalizer(vendor: str, func: Callable[[Row, Mapping], Row]) -> None:
    """Register ``func`` as the normaliser for ``vendor``."""

    key = (vendor or "").strip().lower()
    if not key:
        raise ValueError("Vendor name must be non-empty")
    _NORMALIZERS[key] = func


def apply_vendor_normalizer(vendor: str, row: Row, mapping: Mapping) -> Row:
    """Return a vendor-aware copy of ``row`` ready for ``to_rule``."""

    key = (vendor or "").strip().lower()
    normalizer = _NORMALIZERS.get(key)
    if not normalizer:
        return dict(row)
    return normalizer(row, mapping)
