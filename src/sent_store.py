from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.config import ROOT_DIR

SENT_PATH = ROOT_DIR / "sent_articles.json"
MAX_STORED_URLS = 2000


def _norm(url: str) -> str:
    return (url or "").strip().rstrip("/").lower()


def load_sent_urls() -> set[str]:
    if not SENT_PATH.exists():
        return set()
    try:
        data = json.loads(SENT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    urls = data.get("urls", data if isinstance(data, list) else [])
    return {_norm(u) for u in urls if u}


def save_sent_urls(new_urls: list[str]) -> None:
    merged: list[str] = []
    seen: set[str] = set()
    for url in [*new_urls, *sorted(load_sent_urls())]:
        key = _norm(url)
        if not key or key in seen:
            continue
        seen.add(key)
        merged.append(url.strip())
    payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "urls": merged[:MAX_STORED_URLS],
    }
    SENT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
