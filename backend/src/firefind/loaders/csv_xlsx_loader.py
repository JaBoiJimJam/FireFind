# loaders/csv_xlsx_loader.py
from typing import Dict, Iterator, List
from pathlib import Path
import csv
from openpyxl import load_workbook

def _read_csv_rows(path: Path) -> Iterator[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            row_dict = { (k or "").strip(): (str(v) if v is not None else "") for k, v in row.items() }
            # Skip section headings and noise: require a numeric Seq # when present
            if "Seq #" in row_dict:
                seq = row_dict.get("Seq #", "").strip()
                if not seq.isdigit():
                    continue
            yield row_dict

def _read_xlsx_rows(path: Path) -> Iterator[Dict[str, str]]:
    wb = load_workbook(filename=str(path), read_only=True, data_only=True)
    ws = wb.active

    # find the header row
    header_row_idx = None
    for i, row in enumerate(ws.iter_rows(values_only=True), start=1):
        cells = [str(c).strip() if c is not None else "" for c in row]
        if {"Seq #", "Action", "Service"} <= set(cells):
            header_row_idx = i
            headers = cells
            break

    if header_row_idx is None:
        # fallback: take the first non-empty row as headers
        ws = wb.active
        ws.reset_dimensions()
        for i, row in enumerate(ws.iter_rows(values_only=True), start=1):
            cells = [str(c).strip() if c is not None else "" for c in row]
            if any(cells):
                header_row_idx = i
                headers = cells
                break

    if header_row_idx is None:
        return

    # iterate rows after header
    for row in ws.iter_rows(min_row=header_row_idx+1, values_only=True):
        values = [("" if v is None else str(v).strip()) for v in row]
        # pad to headers length
        if len(values) < len(headers):
            values += [""] * (len(headers) - len(values))
        row_dict = dict(zip(headers, values))

        # Skip section headings and noise: require a numeric Seq # when present
        if "Seq #" in row_dict:
            seq = row_dict.get("Seq #", "").strip()
            if not seq.isdigit():
                continue

        yield row_dict

def load_table(path: Path) -> Iterator[Dict[str, str]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        yield from _read_csv_rows(path)
    elif suffix == ".xlsx":
        yield from _read_xlsx_rows(path)
    else:
        raise ValueError(f"Unsupported file: {path}")
