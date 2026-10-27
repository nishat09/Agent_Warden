"""AgentWarden command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .bench import run_all, run_scenario
from .engine import Session
from .policy import Policy
from .scenarios import SCENARIOS

if os.name == "nt":
    os.system("")  # enable ANSI escape codes on Windows terminals

C = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m", "cyan": "\033[96m",
     "dim": "\033[2m", "bold": "\033[1m", "end": "\033[0m"}
ACTION_COLOR = {"block": "red", "warn": "yellow", "allow": "green"}


def c(text: str, color: str) -> str:
    return f"{C[color]}{text}{C['end']}" if sys.stdout.isatty() else text


def _print_verdict(label: str, v) -> None:
    action = c(f"{v.action.upper():<6}", ACTION_COLOR[v.action])
    print(f"  {label:<34} {action} risk={v.risk_score:>3}")
    for f in v.findings:
        print(c(f"      - [{f.severity.name}] {f.detector}: {f.message}", "dim"))


def cmd_bench(args) -> int:
    report = run_all(Policy.load(args.policy))
    m = report["metrics"]
    if args.json:
        print(json.dumps({"metrics": m, "results": [
            {"id": r.scenario.id, "title": r.scenario.title, "malicious": r.scenario.malicious,
             "blocked": r.blocked, "max_risk": r.max_risk, "detectors": r.detectors}
            for r in report["results"]]}, indent=2))
        return 0
    print(c("\nAgentWarden benchmark\n", "bold"))
    for r in report["results"]:
        mark = c("PASS", "green") if r.correct else c("FAIL", "red")
        outcome = "blocked" if r.blocked else "allowed"
        print(f" {mark}  {r.scenario.id}  {r.scenario.title[:58]:<58} {outcome:<8} risk={r.max_risk:>3}")
    print(f"\n TP={m['tp']} FN={m['fn']} FP={m['fp']} TN={m['tn']}   "
          f"precision={m['precision']}  recall={m['recall']}  F1={m['f1']}\n")
    return 0 if m["fn"] == 0 and m["fp"] == 0 else 1


def cmd_demo(args) -> int:
    ids = [args.scenario] if args.scenario else [s.id for s in SCENARIOS]
    for sc in (s for s in SCENARIOS if s.id in ids):
        print(c(f"\n=== {sc.id}: {sc.title} ===", "cyan"))
        res = run_scenario(sc, Policy.load(args.policy))
        for step, v in zip(sc.steps, res.verdicts):
            label = {"user": "user prompt", "output": f"output <- {step[1]}", "call": f"call -> {step[1]}"}[step[0]]
            _print_verdict(label, v)
    return 0


def cmd_scan(args) -> int:
    text = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    session = Session(policy=Policy.load(args.policy))
    v = session.inspect_call(args.tool, text) if args.as_call else session.inspect_output(args.tool, text)
    if args.json:
        print(json.dumps(v.to_dict(), indent=2))
    else:
        _print_verdict(f"{'call' if args.as_call else 'output'} {args.tool}", v)
    return 2 if v.blocked else 0


def cmd_serve(args) -> int:
    import uvicorn
    uvicorn.run("agentwarden.server:app", host=args.host, port=args.port, reload=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentwarden", description="Runtime security firewall for LLM agents")
    p.add_argument("--policy", help="path to policy YAML (default: built-in)")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bench", help="run attack/benign scenario benchmark")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=cmd_bench)

    d = sub.add_parser("demo", help="replay scenarios step by step")
    d.add_argument("scenario", nargs="?", help="scenario id, e.g. ATK-02")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("scan", help="scan a file / stdin as tool output (or call with --as-call)")
    s.add_argument("file", nargs="?")
    s.add_argument("--tool", default="web_fetch")
    s.add_argument("--as-call", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_scan)

    sv = sub.add_parser("serve", help="start the REST API + dashboard")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
