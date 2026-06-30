#!/usr/bin/env python3

from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def save_report(content, target, mode, domain):
    REPORTS_DIR.mkdir(exist_ok=True)

    safe_target = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"{timestamp}_{domain}_{mode}_{safe_target}.json"
    path = REPORTS_DIR / filename

    path.write_text(content, encoding="utf-8")
    return path
