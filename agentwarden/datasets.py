"""Public evaluation data. Downloaded on demand and cached under ./data (not committed)."""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

DATA_DIR = Path.cwd() / "data"
HF_ROWS = "https://datasets-server.huggingface.co/rows?dataset={ds}&config=default&split={split}&offset={off}&length=100"

# deepset/prompt-injections (Apache-2.0): 662 labelled prompts, EN + DE, label 1 = injection.
DEEPSET = "deepset/prompt-injections"


def load(split: str, dataset: str = DEEPSET) -> list[tuple[str, int]]:
    cache = DATA_DIR / f"{dataset.replace('/', '__')}.{split}.jsonl"
    if not cache.exists():
        rows: list[dict] = []
        off = 0
        while True:
            url = HF_ROWS.format(ds=dataset, split=split, off=off)
            with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 (fixed https host)
                page = json.load(r)["rows"]
            rows += [p["row"] for p in page]
            if len(page) < 100:
                break
            off += 100
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    return [(r["text"], int(r["label"])) for r in map(json.loads, cache.read_text(encoding="utf-8").splitlines())]
