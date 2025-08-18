from typing import Dict, Iterable
from .utils import pick_first_present

NORMALIZED_FIELDS = ["rule_id","src","dst","proto","port","action","comment"]

def map_row_fortinet(row: Dict[str,str], mapping: Dict[str, list]) -> Dict[str,str]:
    """Map a Fortinet-exported row to the normalized schema using mapping hints."""
    out = {}
    for field in NORMALIZED_FIELDS:
        candidates = mapping.get(field, [field])
        out[field] = pick_first_present(row, candidates)
    # basic normalization fallbacks
    out["proto"] = out.get("proto","any") or "any"
    out["port"] = out.get("port","any") or "any"
    out["action"] = (out.get("action","") or "").lower()
    return out
