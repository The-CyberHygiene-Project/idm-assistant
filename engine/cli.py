"""python -m engine collect HOST [--user U] | findings HOST [--user U] | scenario ID [--runs N]"""
import argparse
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from engine import remote
from engine.case import Case
from engine.findings import evaluate
from engine.repairs import REGISTRY, Ctx, run_repair, target_role

ROOT = Path(__file__).resolve().parents[1]
DIAG = {"srv1": "srv1-diag", "client2": "client2-diag"}


def approver():
    if os.environ.get("IDM_TEST_APPROVE") == "1":              # regression runner only; recorded in the case
        return lambda prompt: print(f"[TEST-MODE APPROVAL] {prompt}") or True
    def ask(prompt):
        try:
            return input(f"{prompt}: ").strip().lower() == "yes"
        except EOFError:                                         # no answer is not approval
            return False
    return ask


def run_scenario(sc, run_no):
    case = Case(ROOT / "cases", f"{sc.ID}-run{run_no}", sc.SYMPTOM)
    if os.environ.get("IDM_TEST_APPROVE") == "1":
        case.write("test-mode.txt", "approvals in this case were given by the regression runner (IDM_TEST_APPROVE=1)\n")
    with case.step("reset"):
        subprocess.run([str(ROOT / "lab" / "reset.sh"), "srv1", "client2"], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
    with case.step("inject"):
        sc.inject(case.log)
    got, reps = {}, {}
    with case.step("collect"):
        for h in sc.EXPECT:
            reps[h] = rep = remote.collect(DIAG[h], sc.USER if h == "srv1" else None)
            case.write(f"report-before-{h}.json", rep)
            got[h] = {f.id for f in evaluate(rep)}
    case.write("findings.json", {h: sorted(v) for h, v in got.items()})
    missing = {h: sorted(sc.EXPECT[h] - got[h]) for h in sc.EXPECT if sc.EXPECT[h] - got[h]}
    if missing:
        case.log(f"EXPECTED FINDINGS MISSING: {missing}"); case.write("status.txt", "DIAGNOSIS-FAILED\n")
        return case, "DIAGNOSIS-FAILED"
    for host, rid in sc.REPAIRS:
        ctx = Ctx(host=host, role=target_role(reps[host], host), case=case,
                  collect=lambda h=host: remote.collect(DIAG[h], sc.USER if h == "srv1" else None), remote=remote,
                  params=dict(getattr(sc, "PARAMS", {})))
        st = run_repair(rid, ctx, approver(), REGISTRY)
        if st != "OK":
            return case, f"REPAIR-{st}"
    with case.step("final-check"):
        final = {}
        for _ in range(12):                                      # clients may need a moment to reconnect
            final = {h: sorted(f.id for f in evaluate(remote.collect(DIAG[h], sc.USER if h == "srv1" else None)))
                     for h in sc.EXPECT}
            if not any(final.values()):
                break
            time.sleep(5)
    case.write("findings-final.json", final)
    probe_ok = sc.final_probe(case.log) if hasattr(sc, "final_probe") else True
    status = "GREEN" if not any(final.values()) and probe_ok else "NOT-CLEARED"
    case.write("status.txt", status + "\n")
    return case, status


def main(argv=None):
    ap = argparse.ArgumentParser(prog="engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("collect", "findings"):
        p = sub.add_parser(c); p.add_argument("host"); p.add_argument("--user")
    p = sub.add_parser("scenario"); p.add_argument("id"); p.add_argument("--runs", type=int, default=1)
    a = ap.parse_args(argv)
    if a.cmd in ("collect", "findings"):
        rep = remote.collect(DIAG[a.host], a.user)
        print(json.dumps(rep if a.cmd == "collect" else [f.__dict__ for f in evaluate(rep)], indent=1, default=list))
        return 0
    sc = importlib.import_module(f"scenarios.{a.id}")
    results = []
    for n in range(1, a.runs + 1):
        case, st = run_scenario(sc, n)
        results.append(st); print(f"{sc.ID} run {n}: {st}  ({case.dir.relative_to(ROOT)})  timings {case.timings}")
    return 0 if all(s == "GREEN" for s in results) else 1


if __name__ == "__main__":
    sys.exit(main())
