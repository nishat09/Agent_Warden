"""REST API + dashboard. Agents call these endpoints around every tool step."""
from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__
from .bench import run_all
from .engine import Session
from .policy import Policy

app = FastAPI(title="AgentWarden", version=__version__,
              description="Runtime security firewall for LLM agents")

POLICY = Policy.load()
SESSIONS: dict[str, Session] = {}
EVENTS: deque[dict[str, Any]] = deque(maxlen=500)
MAX_SESSIONS = 1000
DASHBOARD = Path(__file__).parent / "static" / "dashboard.html"


class PromptIn(BaseModel):
    text: str = Field(max_length=200_000)


class OutputIn(BaseModel):
    tool: str = Field(max_length=200)
    content: str = Field(max_length=500_000)


class CallIn(BaseModel):
    tool: str = Field(max_length=200)
    args: dict[str, Any] | str


def _session(sid: str) -> Session:
    if sid not in SESSIONS:
        raise HTTPException(404, "unknown session")
    return SESSIONS[sid]


def _record(session: Session) -> dict[str, Any]:
    event = session.events[-1]
    EVENTS.append(event)
    return event


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> str:
    return DASHBOARD.read_text(encoding="utf-8")


@app.get("/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "policy": POLICY.name}


@app.post("/v1/sessions")
def create_session() -> dict[str, str]:
    if len(SESSIONS) >= MAX_SESSIONS:
        SESSIONS.pop(next(iter(SESSIONS)))
    s = Session(policy=POLICY)
    SESSIONS[s.session_id] = s
    return {"session_id": s.session_id}


@app.post("/v1/sessions/{sid}/prompt")
def prompt(sid: str, body: PromptIn) -> dict[str, Any]:
    s = _session(sid)
    s.user_prompt(body.text)
    return _record(s)


@app.post("/v1/sessions/{sid}/output")
def output(sid: str, body: OutputIn) -> dict[str, Any]:
    s = _session(sid)
    s.inspect_output(body.tool, body.content)
    return _record(s)


@app.post("/v1/sessions/{sid}/call")
def call(sid: str, body: CallIn) -> dict[str, Any]:
    s = _session(sid)
    s.inspect_call(body.tool, body.args)
    return _record(s)


@app.get("/v1/events")
def events(limit: int = 100) -> list[dict[str, Any]]:
    return list(EVENTS)[-limit:][::-1]


@app.get("/v1/bench")
def bench() -> dict[str, Any]:
    report = run_all(POLICY)
    return {"metrics": report["metrics"], "results": [
        {"id": r.scenario.id, "title": r.scenario.title, "category": r.scenario.category,
         "malicious": r.scenario.malicious, "blocked": r.blocked, "max_risk": r.max_risk,
         "detectors": r.detectors, "reference": r.scenario.reference,
         "steps": [{"stage": v.stage, "target": v.target, "action": v.action, "risk": v.risk_score,
                    "findings": [f.to_dict() for f in v.findings]} for v in r.verdicts]}
        for r in report["results"]]}
