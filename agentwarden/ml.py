"""Learned prompt-injection classifier (char n-gram TF-IDF + logistic regression).

Training uses scikit-learn (optional `[ml]` extra). The trained model is exported
to plain JSON and scored here in pure Python, so the runtime has no ML
dependencies and never unpickles anything: loading a pickled model from disk
is an arbitrary-code-execution risk.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "weights" / "injection_clf.json"
_WS = re.compile(r"\s\s+")


class InjectionClassifier:
    def __init__(self, model: dict):
        self.min_n, self.max_n = model["ngram_range"]
        self.vocab: dict[str, int] = model["vocabulary"]
        self.idf: list[float] = model["idf"]
        self.coef: list[float] = model["coef"]
        self.intercept: float = model["intercept"]
        self.threshold: float = model.get("threshold", 0.5)
        self.meta: dict = model.get("meta", {})

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "InjectionClassifier":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def _ngrams(self, text: str) -> list[str]:
        # Mirrors sklearn's analyzer="char_wb"
        out = []
        for w in _WS.sub(" ", text.lower()).split():
            w = f" {w} "
            for n in range(self.min_n, self.max_n + 1):
                offset = 0
                out.append(w[offset:offset + n])
                while offset + n < len(w):
                    offset += 1
                    out.append(w[offset:offset + n])
                if offset == 0:
                    break
        return out

    def predict_proba(self, text: str) -> float:
        counts = Counter(i for g in self._ngrams(text) if (i := self.vocab.get(g)) is not None)
        if not counts:
            return 1 / (1 + math.exp(-self.intercept))
        weights = {i: (1 + math.log(tf)) * self.idf[i] for i, tf in counts.items()}
        norm = math.sqrt(sum(v * v for v in weights.values())) or 1.0
        z = self.intercept + sum(self.coef[i] * v / norm for i, v in weights.items())
        return 1 / (1 + math.exp(-z))


@lru_cache(maxsize=1)
def default_classifier() -> InjectionClassifier | None:
    return InjectionClassifier.load() if MODEL_PATH.exists() else None


def train(out_path: Path = MODEL_PATH) -> dict:
    """Train on the deepset train split; pick C by 5-fold CV on train only."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import GridSearchCV
    from sklearn.pipeline import Pipeline

    from .datasets import DEEPSET, load

    texts, labels = zip(*load("train"))
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True,
                                  min_df=2, max_features=20000)),
        ("lr", LogisticRegression(max_iter=3000, class_weight="balanced")),
    ])
    grid = GridSearchCV(pipe, {"lr__C": [0.5, 1, 2, 4, 8, 16]}, cv=5, scoring="f1").fit(texts, labels)
    vec, lr = grid.best_estimator_.named_steps["tfidf"], grid.best_estimator_.named_steps["lr"]
    vocab = {k: int(v) for k, v in vec.vocabulary_.items()}
    model = {
        "ngram_range": list(vec.ngram_range),
        "vocabulary": vocab,
        "idf": [round(float(x), 6) for x in vec.idf_],
        "coef": [round(float(x), 6) for x in lr.coef_[0]],
        "intercept": float(lr.intercept_[0]),
        "threshold": 0.5,
        "meta": {"dataset": DEEPSET, "split": "train", "n_train": len(texts),
                 "best_C": float(grid.best_params_["lr__C"]), "cv_f1": round(float(grid.best_score_), 4)},
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(model, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    default_classifier.cache_clear()
    return model["meta"]
