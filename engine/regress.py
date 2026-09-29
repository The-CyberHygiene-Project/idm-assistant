"""Run scenarios N times from golden and write a Markdown regression report."""
import importlib
import json
from statistics import median

DEFAULT = ["l1", "c1", "l2", "l3", "l3n", "l4", "c2"]


def _model(rows):
    used = [r["interp"] for r in rows if "skipped" not in r["interp"]]
    if not used:
        return "skipped"
    return (f"{sum(1 for i in used if i.get('valid'))}/{len(used)} valid, "
            f"{sum(1 for i in used if i.get('agrees'))}/{len(used)} agree")


def _median(rows, key):
    v = [r["timings"][key] for r in rows if key in r["timings"]]
    return f"{median(v):.1f}" if v else ""


def summarize(rows):
    ids = list(dict.fromkeys(r["id"] for r in rows))
    out = ["| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |",
           "|---|---|---|---|---|---|---|---|"]
    all_green = 0
    for sid in ids:
        rs = [r for r in rows if r["id"] == sid]
        g = sum(1 for r in rs if r["status"] == "GREEN")
        all_green += g == len(rs)
        rep = [sum(v for k, v in r["timings"].items() if ":" in k) for r in rs]    # repair steps are "<id>:<step>"
        out.append(f"| {sid} | {len(rs)} | {g}/{len(rs)} | {', '.join(r['status'] for r in rs)} | "
                   f"{_median(rs, 'reset')} | {_median(rs, 'inject')} | {median(rep):.1f} | {_model(rs)} |")
    out += ["", f"**Overall: {all_green} of {len(ids)} scenarios green in every run.**"]
    return "\n".join(out) + "\n"


def run(ids, runs):
    from engine.cli import run_scenario
    rows = []
    for sid in ids:
        sc = importlib.import_module(f"scenarios.{sid}")
        for n in range(1, runs + 1):
            case, st = run_scenario(sc, n)
            p = case.dir / "interpretation.json"
            rows.append({"id": sid, "run": n, "status": st, "timings": dict(case.timings), "case": case.dir.name,
                         "interp": json.loads(p.read_text()) if p.exists() else {"skipped": "not reached"}})
            print(f"{sid} run {n}: {st}", flush=True)
    return rows
