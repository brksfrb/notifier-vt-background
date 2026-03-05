"""
extract_schedule.py
-------------------
Parses Turkish high-school timetable PDFs → JSON matching Dart models.

Two supported formats:
  Format 1 (ÖğretmenEl): "Sayın : NAME" in header or at end of previous page
  Format 2 (input.pdf):  "Adı Soyadı: NAME" in header

JSON output:
  {
    "ok": true,
    "hours_from_pdf": true,
    "hours": ["08:20-09:00", ...],
    "teachers": [
      {
        "index": 0,
        "name": "AYŞEGÜL KOÇ",
        "total_hours": 12,
        "schedule": [          # 5 days × N periods; null = empty slot
          [null, {"grade":11,"section":"A","subject_code":"BDN"}, ...],
          ...
        ]
      }
    ]
  }
  On error: { "ok": false, "error": "..." }
"""

import pdfplumber
import re
import json
import sys
from typing import Optional


DAYS = ["Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma"]
_CELL_RE = re.compile(r"^(\d+)[/\-]([A-Za-z]+)\s+(.+)$", re.DOTALL)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _clean(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return re.sub(r"\s+", " ", raw.replace("\n", " ")).strip() or None


def _parse_cell(raw: Optional[str]) -> Optional[dict]:
    """'12/A BDN' or '9/A\\nBD\\nN' → {grade, section, subject_code}"""
    text = _clean(raw)
    if not text:
        return None
    m = _CELL_RE.match(text)
    if not m:
        return None
    # Remove internal spaces from PDF-wrapped codes like "BD N" → "BDN"
    code = re.sub(r"\s+", "", m.group(3).strip())
    return {
        "grade": int(m.group(1)),
        "section": m.group(2).upper(),
        "subject_code": code,
    }


def _find_teacher_name(text: str) -> Optional[str]:
    # Format 1: "Sayın : NAME"
    m = re.search(r"Sayın\s*:\s*(.+)", text)
    if m:
        return m.group(1).strip()
    # Format 2: "Adı Soyadı: NAME  Eğitici Kol: ..."
    m = re.search(r"Adı Soyadı\s*:\s*(.+?)(?:\s{2,}|\t|Eğitici|Nöbet|$)", text)
    if m:
        return m.group(1).strip()
    return None


def _extract_total_hours(text: str) -> Optional[int]:
    m = re.search(r"Toplam\s*:\s*(\d+)", text)
    return int(m.group(1)) if m else None


def _extract_hours(header_row: list) -> list[str]:
    """First table row → ["08:20-09:00", ...]"""
    hours = []
    for cell in header_row[1:]:
        if not cell:
            continue
        lines = [l.strip() for l in cell.split("\n") if l.strip()]
        times = [l for l in lines if re.match(r"\d{2}:\d{2}", l)]
        if len(times) >= 2:
            hours.append(f"{times[0]}-{times[1]}")
        elif len(times) == 1:
            hours.append(times[0])
    return hours


def _is_schedule_table(table: list) -> bool:
    """
    Returns True only if the first row contains period headers (numbers + time ranges)
    and subsequent rows start with day names. Rejects subject legend tables.
    """
    if not table or len(table) < 2:
        return False
    # Header row: first cell empty/None, rest should contain time-like content
    header = table[0]
    if len(header) < 2:
        return False
    has_times = any(
        re.search(r"\d{2}:\d{2}", str(cell or ""))
        for cell in header[1:]
    )
    if not has_times:
        return False
    # At least one row must start with a known day name
    day_found = any(
        (row[0] or "").strip() in DAYS
        for row in table[1:]
    )
    return day_found


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def extract_format_2(path: str) -> dict:
    teachers = []
    global_hours: list[str] = []

    try:
        with pdfplumber.open(path) as pdf:
            page_texts = [p.extract_text() or "" for p in pdf.pages]

            for idx, page in enumerate(pdf.pages):
                text = page_texts[idx]

                # Only use the schedule grid table — skip any other tables
                all_tables = page.extract_tables()
                table = next((t for t in all_tables if _is_schedule_table(t)), None)
                if not table:
                    continue

                # ── Teacher name ──────────────────────────────────────────
                name = _find_teacher_name(text)
                # Spillover: name appended to bottom of previous page
                if name is None and idx > 0:
                    prev = page_texts[idx - 1]
                    matches = list(re.finditer(r"Sayın\s*:\s*(.+)", prev))
                    if len(matches) >= 2:
                        # Multiple "Sayın" — last one is the spillover
                        name = matches[-1].group(1).strip()
                    elif len(matches) == 1:
                        # Single "Sayın" — only use if it's in the last 30% of text
                        if matches[0].start() > len(prev) * 0.7:
                            name = matches[0].group(1).strip()

                # ── Period headers ────────────────────────────────────────
                hours = _extract_hours(table[0])
                if hours and not global_hours:
                    global_hours = hours
                n_periods = len(table[0]) - 1

                # ── Build 5×n grid ────────────────────────────────────────
                day_rows = {
                    row[0].strip(): row[1:]
                    for row in table[1:]
                    if row[0] and row[0].strip() in DAYS
                }

                grid: list[list] = []
                for day in DAYS:
                    raw_row = day_rows.get(day, [])
                    raw_row = (list(raw_row) + [None] * n_periods)[:n_periods]
                    grid.append([_parse_cell(cell) for cell in raw_row])

                teachers.append({
                    "index": len(teachers),
                    "name": name or "UNKNOWN",
                    "total_hours": _extract_total_hours(text),
                    "schedule": grid,
                })

        return {
            "ok": True,
            "hours_from_pdf": bool(global_hours),
            "hours": global_hours,
            "teachers": teachers,
        }

    except Exception as exc:
        return {"ok": False, "error": str(exc)}


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "program.pdf"
    result = extract_format_2(path)
    print(json.dumps(result, ensure_ascii=False, indent=2))