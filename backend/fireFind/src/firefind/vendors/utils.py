from typing import Dict, List

def pick_first_present(row: Dict[str,str], candidates: List[str]) -> str:
    for c in candidates:
        if c in row and str(row[c]).strip() != "":
            return str(row[c]).strip()
    return ""
