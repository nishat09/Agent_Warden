from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Severity

DEFAULT_POLICY_PATH = Path(__file__).parent / "policies" / "default.yaml"


@dataclass
class Policy:
    name: str = "default"
    warn_threshold: int = 25
    block_threshold: int = 50
    untrusted_sources: set[str] = field(default_factory=set)
    sinks: dict[str, Severity] = field(default_factory=dict)
    denied_tools: set[str] = field(default_factory=set)
    allowed_domains: list[str] = field(default_factory=list)
    allowed_email_domains: list[str] = field(default_factory=list)
    sanitize_outputs: bool = True

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Policy":
        data = yaml.safe_load(Path(path or DEFAULT_POLICY_PATH).read_text(encoding="utf-8")) or {}
        th = data.get("thresholds", {})
        return cls(
            name=data.get("name", "custom"),
            warn_threshold=int(th.get("warn", 25)),
            block_threshold=int(th.get("block", 50)),
            untrusted_sources=set(data.get("untrusted_sources", [])),
            sinks={k: Severity[(v or {}).get("taint_severity", "HIGH")] for k, v in data.get("sinks", {}).items()},
            denied_tools=set(data.get("denied_tools", [])),
            allowed_domains=list(data.get("allowed_domains", [])),
            allowed_email_domains=list(data.get("allowed_email_domains", [])),
            sanitize_outputs=bool(data.get("sanitize_outputs", True)),
        )
