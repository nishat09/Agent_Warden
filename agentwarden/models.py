from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action:
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class Finding:
    detector: str
    severity: Severity
    message: str
    evidence: str = ""
    mitre_atlas: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class Verdict:
    action: str
    risk_score: int
    findings: list[Finding] = field(default_factory=list)
    stage: str = ""
    target: str = ""
    sanitized: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "risk_score": self.risk_score,
            "stage": self.stage,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "sanitized": self.sanitized,
        }
