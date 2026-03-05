"""
test_extract_schedule.py
------------------------
Manual test script for the /extract_schedule endpoint.
Run with:
    python test_extract_schedule.py [pdf_path] [base_url]

Defaults:
    pdf_path = program2.pdf
    base_url = http://localhost:8000

Set REQUIRE_INTEGRITY=false on the server during local testing,
or pass a real token via the X_INTEGRITY_TOKEN env var.
"""

import sys
import os
import json
import requests

PDF_PATH  = sys.argv[1] if len(sys.argv) > 1 else "program5.pdf"
BASE_URL  = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
TOKEN     = os.environ.get("X_INTEGRITY_TOKEN")  # optional

url = f"{BASE_URL}/extract_schedule"

print(f"POST {url}")
print(f"File: {PDF_PATH}")
print(f"Integrity token: {'yes' if TOKEN else 'none (set X_INTEGRITY_TOKEN to include)'}")
print()

headers = {}
if TOKEN:
    headers["x-integrity-token"] = TOKEN

with open(PDF_PATH, "rb") as f:
    response = requests.post(
        url,
        files={"file": (os.path.basename(PDF_PATH), f, "application/pdf")},
        headers=headers,
        timeout=30,
    )

print(f"Status: {response.status_code}")

if response.status_code != 200:
    print(f"Error: {response.text}")
    sys.exit(1)

data = response.json()

print(f"ok:            {data['ok']}")
print(f"hours_from_pdf:{data['hours_from_pdf']}")
print(f"hours:         {data['hours']}")
print(f"teachers:      {len(data['teachers'])}")
print()

for t in data["teachers"]:
    total = t["total_hours"]
    slots = sum(1 for day in t["schedule"] for s in day if s is not None)
    print(f"  [{t['index']}] {t['name']}  total_hours={total}  filled_slots={slots}")
    for d, (day_name, periods) in enumerate(
        zip(["Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma"], t["schedule"])
    ):
        non_null = [(i + 1, s) for i, s in enumerate(periods) if s]
        for p, s in non_null:
            print(f"       {day_name[:3]} P{p}: {s['grade']}/{s['section']} {s['subject_code']}")
    print()

print("Full JSON saved to: extract_schedule_result.json")
with open("extract_schedule_result.json", "w", encoding="utf-8") as out:
    json.dump(data, out, ensure_ascii=False, indent=2)