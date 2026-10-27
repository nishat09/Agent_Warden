"""Replay scenarios through AgentWarden and compute detection metrics."""
from __future__ import annotations

from dataclasses import dataclass, field

from .engine import Session
from .models import Verdict
from .policy import Policy
from .scenarios import SCENARIOS, Scenario


@dataclass
class ScenarioResult:
    scenario: Scenario
    verdicts: list[Verdict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(v.blocked for v in self.verdicts)

    @property
    def max_risk(self) -> int:
        return max((v.risk_score for v in self.verdicts), default=0)

    @property
    def correct(self) -> bool:
        return self.blocked == self.scenario.malicious

    @property
    def detectors(self) -> list[str]:
        return sorted({f.detector for v in self.verdicts for f in v.findings})


def run_scenario(sc: Scenario, policy: Policy | None = None) -> ScenarioResult:
    session = Session(policy=policy or Policy.load())
    res = ScenarioResult(sc)
    for step in sc.steps:
        kind = step[0]
        if kind == "user":
            res.verdicts.append(session.user_prompt(step[1]))
        elif kind == "output":
            res.verdicts.append(session.inspect_output(step[1], step[2]))
        elif kind == "call":
            res.verdicts.append(session.inspect_call(step[1], step[2]))
    return res


def run_all(policy: Policy | None = None) -> dict:
    results = [run_scenario(s, policy) for s in SCENARIOS]
    tp = sum(r.scenario.malicious and r.blocked for r in results)
    fn = sum(r.scenario.malicious and not r.blocked for r in results)
    fp = sum(not r.scenario.malicious and r.blocked for r in results)
    tn = sum(not r.scenario.malicious and not r.blocked for r in results)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "results": results,
        "metrics": {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
                    "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)},
    }
