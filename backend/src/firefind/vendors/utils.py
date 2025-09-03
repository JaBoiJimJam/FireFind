from typing import Dict, List

def pick_first_present(row: Dict[str,str], candidates: List[str]) -> str:
    for c in candidates:
        if c in row and str(row[c]).strip() != "":
            return str(row[c]).strip()
    return ""

def normalize_header(h: str) -> str:
    """Normalize header strings for consistent mapping."""
    return h.strip().lower().replace(" ", "_") if h else ""
