from typing import Dict, List


def pick_first_present(row: Dict[str, str], candidates: List[str]) -> str:
    """Return the first non-empty value for any of ``candidates`` in ``row``.

    The exported spreadsheets we ingest are inconsistent about their column
    casing (for example ``Action`` vs ``action``).  The original implementation
    only looked for an exact key match which meant entirely valid rows from the
    Client 2 sample files were treated as empty because their headers were all
    lowercase.  By normalising the headers we can treat these columns as
    equivalent and ensure the records are processed correctly.
    """

    for candidate in candidates:
        value = row.get(candidate)
        if value is not None and str(value).strip() != "":
            return str(value).strip()

    if not row:
        return ""

    # Build lookup tables for normalised and lower-cased keys so we only pay
    # the normalisation cost once per call.
    normalised = {normalize_header(k): v for k, v in row.items() if k is not None}
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}

    for candidate in candidates:
        norm_key = normalize_header(candidate)
        if norm_key in normalised:
            value = normalised[norm_key]
            if value is not None and str(value).strip() != "":
                return str(value).strip()

        lower_key = candidate.strip().lower()
        if lower_key in lowered:
            value = lowered[lower_key]
            if value is not None and str(value).strip() != "":
                return str(value).strip()

    return ""


def normalize_header(h: str) -> str:
    """Normalize header strings for consistent mapping."""

    return h.strip().lower().replace(" ", "_") if h else ""


_ACTION_SYNONYMS = {
    "accept": "allow",
    "allow": "allow",
    "pass": "allow",
    "permit": "allow",
    "enable": "allow",
    "enabled": "allow",
    "drop": "deny",
    "deny": "deny",
    "block": "deny",
    "blocked": "deny",
    "reject": "deny",
    "discard": "deny",
    "disable": "deny",
    "disabled": "deny",
    "refuse": "deny",
    "monitor": "monitor",
    "log": "monitor",
}


def normalize_action(value: str, default: str = "allow") -> str:
    """Return a canonical action keyword for heterogeneous exports."""

    raw = (value or "").strip()
    if not raw:
        raw = default

    lowered = raw.lower()
    normalised = _ACTION_SYNONYMS.get(lowered)
    if normalised:
        return normalised

    return lowered
