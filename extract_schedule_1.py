"""
extract_format_1.py
-------------------
Parses Turkish middle-school all-teachers-on-one-page timetable PDFs → JSON
matching the same schema as extract_format_2.py (extract_schedule.py).

Supported format:
  A single-page (or multi-page) PDF where ALL teachers are listed in a compact
  grid.  Each teacher occupies two interleaved rows:
    SUBJ row  (e.g. REH, MAT)  — rendered above THIS teacher's label
    CLASS row (e.g. 8C, 5A)    — rendered below PREVIOUS teacher's label
  with the teacher's label row (name + total hours) sitting between them.

  There are no time-of-day headers; hours are identified by column index (1–8).

JSON output schema (identical to extract_format_2.py):
  {
    "ok": true,
    "hours_from_pdf": false,
    "hours": [],
    "teachers": [
      {
        "index": 0,
        "name": "ETHEM KORKUT",
        "total_hours": 26,
        "schedule": [          # 5 days × 8 periods; null = empty slot
          [
            {"grade": 8, "section": "C", "subject_code": "REH"},
            {"grade": 5, "section": "A", "subject_code": "MAT"},
            ...
            null,
            null,
            null
          ],
          ...                  # Salı, Çarşamba, Perşembe, Cuma
        ]
      },
      ...
    ]
  }
  On error: { "ok": false, "error": "..." }

Usage:
    python extract_format_1.py [path/to/program5.pdf]
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import pdfplumber


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DAY_LABELS = ["Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma"]
HOURS_PER_DAY = 8
TOTAL_SLOTS = len(DAY_LABELS) * HOURS_PER_DAY  # 40

CLASS_CODE_RE = re.compile(r"^[5-8][A-C]$")


# ─────────────────────────────────────────────────────────────────────────────
# Internal data model (private to this module)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Slot:
    class_code: Optional[str] = None   # e.g. "8C"
    subject: Optional[str] = None      # e.g. "MAT"

    def is_empty(self) -> bool:
        return self.class_code is None and self.subject is None

    def to_json(self) -> Optional[dict]:
        """Convert to the JSON cell format used by extract_format_2."""
        if self.is_empty():
            return None
        # class_code "8C" → grade=8, section="C"
        grade: Optional[int] = None
        section: Optional[str] = None
        if self.class_code and len(self.class_code) == 2:
            try:
                grade = int(self.class_code[0])
                section = self.class_code[1].upper()
            except ValueError:
                pass
        return {
            "grade": grade,
            "section": section,
            "subject_code": self.subject,
        }


@dataclass
class _Schedule:
    teacher: str
    total_hours: int
    # days[day_label] = list of HOURS_PER_DAY _Slot objects
    days: dict[str, list[_Slot]] = field(default_factory=dict)

    def to_json(self, index: int) -> dict:
        grid = []
        for day_label in DAY_LABELS:
            slots = self.days.get(day_label, [_Slot()] * HOURS_PER_DAY)
            grid.append([s.to_json() for s in slots])
        return {
            "index": index,
            "name": self.teacher,
            "total_hours": self.total_hours,
            "schedule": grid,
        }


# ─────────────────────────────────────────────────────────────────────────────
# PDF word extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

def _group_by_row(words: list[dict]) -> dict[float, list[dict]]:
    rows: dict[float, list[dict]] = defaultdict(list)
    for w in words:
        rows[round(w["top"], 0)].append(w)
    return rows


def _cx(w: dict) -> float:
    return (w["x0"] + w["x1"]) / 2


def _nearest_slot(x: float, slot_xs: list[float]) -> int:
    return min(range(len(slot_xs)), key=lambda i: abs(x - slot_xs[i]))


def _find_slot_xs(rows: dict[float, list[dict]]) -> list[float]:
    """
    Dynamically locate the 40-column hour-header row (digits 1-8 repeated 5×)
    and return the x-centre of each column.  No hardcoded positions.
    """
    for y in sorted(rows):
        row = sorted(rows[y], key=lambda w: w["x0"])
        texts = [w["text"] for w in row]
        if len(texts) >= 38 and all(t in "12345678" for t in texts):
            return [round(_cx(w), 2) for w in row][:TOTAL_SLOTS]
    raise ValueError("Cannot find the 40-column hour-header row.")


def _parse_label_row(row_words: list[dict]) -> tuple[str, int]:
    """Extract (teacher_name, total_hours) from a teacher label row."""
    label = sorted([w for w in row_words if w["x0"] < 85], key=lambda w: w["x0"])
    hours, name_tokens = 0, []
    for w in label:
        t = w["text"]
        if re.fullmatch(r"\d+-", t):            # skip "1-", "13-" prefix
            continue
        if re.fullmatch(r"\d+", t) and w["x0"] >= 70:   # total-hours number
            hours = int(t)
        else:
            name_tokens.append(t)
    return " ".join(name_tokens), hours


def _classify_band(
    rows: dict[float, list[dict]],
    sorted_ys: list[float],
    lo: float,
    hi: float,
) -> tuple[Optional[float], Optional[float]]:
    """
    Within the y window (lo, hi) exclusive, find:
      - class_row_y: first word matches CLASS_CODE_RE (e.g. "8C")
      - subj_row_y:  first word is a subject code (e.g. "MAT")
    """
    class_row_y: Optional[float] = None
    subj_row_y: Optional[float] = None
    for dy in sorted_ys:
        if dy <= lo or dy >= hi:
            continue
        data = [w for w in rows[dy] if w["x0"] >= 85]
        if not data:
            continue
        first = sorted(data, key=lambda w: w["x0"])[0]["text"]
        if CLASS_CODE_RE.match(first):
            class_row_y = dy
        else:
            subj_row_y = dy
    return class_row_y, subj_row_y


def _slots_from_row(
    rows: dict[float, list[dict]],
    row_y: Optional[float],
    slot_xs: list[float],
    method: str,
) -> list[Optional[str]]:
    """
    Build a TOTAL_SLOTS-length list of token strings for one data row.

    method="positional": assign each word to nearest slot by x-centre.
    method="textual":    determine occupied slots by x-centre (structure),
                         then assign tokens by left-to-right order (content).
    """
    result: list[Optional[str]] = [None] * TOTAL_SLOTS
    if row_y is None:
        return result

    words_sorted = sorted(
        [w for w in rows[row_y] if w["x0"] >= 85], key=lambda w: w["x0"]
    )

    if method == "positional":
        for w in words_sorted:
            result[_nearest_slot(_cx(w), slot_xs)] = w["text"]
    else:
        occupied, seen = [], set()
        for w in words_sorted:
            si = _nearest_slot(_cx(w), slot_xs)
            if si not in seen:
                occupied.append(si)
                seen.add(si)
        for si, w in zip(occupied, words_sorted):
            result[si] = w["text"]

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Core extraction (dual-method + cross-validation)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_raw(
    rows: dict[float, list[dict]],
    sorted_ys: list[float],
    teacher_ys: list[float],
    slot_xs: list[float],
    method: str,
) -> list[tuple[str, int, list, list]]:
    """
    Returns list of (name, total_hours, class_slots[40], subj_slots[40]).

    Layout rule:
      Between two consecutive label rows (prev_label, this_label):
        CLASS row → belongs to THIS teacher
        SUBJ row  → belongs to the PREVIOUS teacher
      The last teacher's subject row appears after its own label.
    """
    n = len(teacher_ys)
    all_cls: list[list[Optional[str]]] = [[None] * TOTAL_SLOTS for _ in range(n)]
    all_sub: list[list[Optional[str]]] = [[None] * TOTAL_SLOTS for _ in range(n)]
    names: list[str] = []
    hours_list: list[int] = []

    for t_idx, ty in enumerate(teacher_ys):
        name, hrs = _parse_label_row(sorted(rows[ty], key=lambda w: w["x0"]))
        names.append(name)
        hours_list.append(hrs)

        prev_ty = teacher_ys[t_idx - 1] if t_idx > 0 else 0.0
        class_row_y, subj_row_y = _classify_band(rows, sorted_ys, prev_ty, ty)

        all_cls[t_idx] = _slots_from_row(rows, class_row_y, slot_xs, method)
        if t_idx > 0:
            all_sub[t_idx - 1] = _slots_from_row(rows, subj_row_y, slot_xs, method)

        # Last teacher: grab its subject row from the band after its own label
        if t_idx == n - 1:
            _, last_subj_y = _classify_band(
                rows, sorted_ys, ty, max(sorted_ys) + 1
            )
            if last_subj_y is not None:
                all_sub[t_idx] = _slots_from_row(rows, last_subj_y, slot_xs, method)

    return list(zip(names, hours_list, all_cls, all_sub))


def _cross_validate(
    a_results: list[tuple],
    b_results: list[tuple],
) -> list[_Schedule]:
    """
    Merge Method A (positional) and Method B (textual) slot-by-slot.
    Agreement → use value.  One side None → use non-None.
    Conflict  → prefer Method A (positional), slot still populated.
    """
    schedules: list[_Schedule] = []

    for (a_name, a_hrs, a_cls, a_sub), (b_name, b_hrs, b_cls, b_sub) in zip(
        a_results, b_results
    ):
        days: dict[str, list[_Slot]] = {}

        for d, day_label in enumerate(DAY_LABELS):
            slots: list[_Slot] = []
            for h in range(HOURS_PER_DAY):
                si = d * HOURS_PER_DAY + h
                slot = _Slot()

                ac, bc = a_cls[si], b_cls[si]
                slot.class_code = ac if ac == bc else (ac or bc)

                as_, bs = a_sub[si], b_sub[si]
                slot.subject = as_ if as_ == bs else (as_ or bs)

                slots.append(slot)
            days[day_label] = slots

        schedules.append(
            _Schedule(teacher=a_name or b_name, total_hours=a_hrs or b_hrs, days=days)
        )

    return schedules


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def extract_format_1(path: str) -> dict:
    """
    Parse an all-teachers-on-one-page weekly schedule PDF and return a JSON-
    serialisable dict matching the extract_format_2 schema.
    """
    try:
        all_schedules: list[_Schedule] = []

        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                words = page.extract_words(x_tolerance=1, y_tolerance=2)
                if not words:
                    continue

                rows = _group_by_row(words)
                sorted_ys = sorted(rows)

                try:
                    slot_xs = _find_slot_xs(rows)
                except ValueError:
                    continue  # page doesn't match expected format

                teacher_ys: list[float] = []
                for y in sorted_ys:
                    row = sorted(rows[y], key=lambda w: w["x0"])
                    if row and row[0]["x0"] < 10 and re.match(r"\d+-$", row[0]["text"]):
                        teacher_ys.append(y)

                if not teacher_ys:
                    continue

                a = _extract_raw(rows, sorted_ys, teacher_ys, slot_xs, "positional")
                b = _extract_raw(rows, sorted_ys, teacher_ys, slot_xs, "textual")
                all_schedules.extend(_cross_validate(a, b))

        return {
            "ok": True,
            "hours_from_pdf": False,
            "hours": [],
            "teachers": [s.to_json(i) for i, s in enumerate(all_schedules)],
        }

    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "program5.pdf"
    result = extract_format_1(path)
    print(json.dumps(result, ensure_ascii=False, indent=2))