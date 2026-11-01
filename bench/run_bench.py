"""Run the benchmark: the same multi-agent team, with and without Patient Zero.

Usage:
  python bench/run_bench.py --provider openai --models gpt-4o-mini --runs 2
  python bench/run_bench.py --provider claude --models claude-sonnet-4-5 --runs 2

Writes bench/results/<model>.jsonl and prints a summary table.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from scenarios import ALL  # noqa: E402

from patientzero import Gateway, Policy, Session, make_model  # noqa: E402
from patientzero.sim import Acme, build_single, build_team, running  # noqa: E402

ROOT = Path(__file__).parent.parent
RESULTS = Path(__file__).parent / "results"


async def run_one(scenario, mode, arch, model, policy, sem):
    async with sem:
        env = Acme()
        scenario.setup(env)
        gateway = Gateway(policy, enforce=(mode == "patient-zero"))
        start = time.perf_counter()
        error = ""
        answer = ""
        trace = []
        tokens = (0, 0)
        try:
            async with running(env, gateway):
                agent = build_team(gateway, model) if arch == "team" else build_single(gateway, model)
                result = await agent.run(Session(task=scenario.task), scenario.task)
                answer, trace = result.answer, result.trace
                tokens = (result.input_tokens, result.output_tokens)
        except Exception as exc:  # keep the benchmark going; record the error
            error = f"{type(exc).__name__}: {exc}"
        latencies = [r["latency_ms"] for r in gateway.audit.records]
        return {
            "scenario": scenario.id, "kind": scenario.kind, "category": scenario.category,
            "mode": mode, "arch": arch, "model": model.model,
            "completed": bool(scenario.completed(env, answer)) and not error,
            "attacked": bool(scenario.attacked(env, answer)),
            "blocked_calls": sum(e.blocked for e in trace),
            "injection_flags": sum(bool(e.injection) for e in trace),
            "tool_calls": sum(1 for e in trace if e.agent != "orchestrator"),
            "gateway_ms": round(sum(latencies), 2),
            "seconds": round(time.perf_counter() - start, 1),
            "input_tokens": tokens[0], "output_tokens": tokens[1],
            "answer": answer[:400], "error": error,
            "sent_emails": env.sent_emails, "posts": env.posts, "sql": env.sql_log,
            "trace": [e.__dict__ for e in trace],
        }


def summarize(rows):
    def rate(rs, key):
        return f"{sum(r[key] for r in rs)}/{len(rs)} ({100 * sum(r[key] for r in rs) / max(len(rs), 1):.0f}%)"
    lines = ["| Model | Agents | Mode | Attack success | Task success (normal) | Task success (under attack) |",
             "| --- | --- | --- | --- | --- | --- |"]
    for model, arch, mode in sorted({(r["model"], r["arch"], r["mode"]) for r in rows}):
        rs = [r for r in rows if r["model"] == model and r["arch"] == arch and r["mode"] == mode]
        if not rs:
            continue
        attacks = [r for r in rs if r["kind"] == "attack"]
        benign = [r for r in rs if r["kind"] == "benign"]
        label = "No protection" if mode == "none" else "Patient Zero"
        lines.append(f"| {model} | {arch} | {label} | {rate(attacks, 'attacked')} | "
                     f"{rate(benign, 'completed')} | {rate(attacks, 'completed')} |")
    return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--models", nargs="+", default=["gpt-4o-mini"])
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--only", nargs="*", help="scenario ids to run, like A1 B1")
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--arch", nargs="+", default=["single", "team"])
    args = parser.parse_args()

    policy = Policy.load(ROOT / "policy.example.yaml")
    scenarios = [s for s in ALL if not args.only or s.id in args.only]
    RESULTS.mkdir(exist_ok=True)
    sem = asyncio.Semaphore(args.concurrency)
    all_rows = []
    for name in args.models:
        model = make_model(args.provider, name)
        jobs = [run_one(s, mode, arch, model, policy, sem)
                for s in scenarios for arch in args.arch
                for mode in ("none", "patient-zero") for _ in range(args.runs)]
        rows = await asyncio.gather(*jobs)
        out = RESULTS / f"{name}.jsonl"
        out.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        all_rows += rows
        errors = [r for r in rows if r["error"]]
        print(f"{name}: {len(rows)} runs, {len(errors)} errors -> {out}")
        for r in errors[:3]:
            print("  error:", r["scenario"], r["mode"], r["error"][:200])
    print()
    print(summarize(all_rows))


if __name__ == "__main__":
    asyncio.run(main())
