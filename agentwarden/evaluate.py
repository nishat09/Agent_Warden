"""Evaluate detectors on a public, held-out dataset (not written by us)."""
from __future__ import annotations

from .datasets import DEEPSET, load
from .detectors import detect_injection, normalize
from .ml import default_classifier
from .models import Severity


def _metrics(pred: list[bool], gold: list[int]) -> dict:
    tp = sum(p and g for p, g in zip(pred, gold))
    fp = sum(p and not g for p, g in zip(pred, gold))
    fn = sum((not p) and g for p, g in zip(pred, gold))
    tn = len(gold) - tp - fp - fn
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 3),
            "recall": round(rc, 3), "f1": round(f1, 3), "accuracy": round((tp + tn) / len(gold), 3)}


def evaluate(split: str = "test") -> dict:
    data = load(split)
    texts, gold = [t for t, _ in data], [g for _, g in data]
    rules = [any(f.severity >= Severity.MEDIUM for f in detect_injection(t)) for t in texts]
    clf = default_classifier()
    ml = [clf.predict_proba(normalize(t)) >= clf.threshold for t in texts] if clf else [False] * len(texts)
    hybrid = [a or b for a, b in zip(rules, ml)]
    return {"dataset": DEEPSET, "split": split, "n": len(texts), "positives": sum(gold),
            "model": clf.meta if clf else None,
            "rules": _metrics(rules, gold), "ml": _metrics(ml, gold), "hybrid": _metrics(hybrid, gold)}
