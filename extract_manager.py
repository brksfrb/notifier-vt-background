from extract_schedule_2 import extract_format_2
from extract_schedule_1 import extract_format_1

def extract_schedule(path: str) -> dict:
    out = extract_format_2(path)
    if out.get("teachers"):
        return out

    out = extract_format_1(path)
    return out