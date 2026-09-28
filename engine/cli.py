"""python -m engine collect HOST [--user U] | findings HOST [--user U] | scenario ID [--runs N]"""
import argparse
import getpass
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from engine import interpret, remote
from engine.case import Case
from engine.findings import evaluate
from engine.repairs import REGISTRY, Ctx, run_repair, target_role

ROOT = Path(__file__).resolve().parents[1]
DIAG = {"srv1": "srv1-diag", "client2": "client2-diag"}


def approver():
    if os.environ.get("IDM_TEST_APPROVE") == "1":              # regression runner only; recorded in the case
        def test_approve(prompt):
            print(f"[TEST-MODE APPROVAL] {prompt}")
            return True
        test_approve.who, test_approve.test_mode = "regression-runner (IDM_TEST_APPROVE=1)", True
        return test_approve

    def ask(prompt):
        try:
            return input(f"{prompt}: ").strip().lower() == "yes"
        except EOFError:                                         # no answer is not approval
            return False
    ask.who, ask.test_mode = getpass.getuser(), False
    return ask


def final_status(final, probe_ok, interp, no_model, elapsed_s, clear_before_s):
    """GREEN = explained (or the model explicitly skipped), every finding cleared, the probe passed, and, where a fault
    would heal by itself, cleared by the repair before nature would have."""
    if interp is not None and not no_model and any(e.startswith("model unavailable") or e == "prompt over budget"
                                                   for e in interp.get("errors", [])):
        return "EXPLAIN-FAILED"
    if any(final.values()) or not probe_ok:
        return "NOT-CLEARED"
    if clear_before_s is not None and elapsed_s is not None and elapsed_s > clear_before_s:
        return "NOT-CLEARED-BY-REPAIR"
    return "GREEN"


def _evaluate_all(reps):
    """Client reports are also judged against the server's view (cross-host rules)."""
    srv = reps.get("srv1")
    return {h: evaluate(r, srv if r.get("role") == "client" else None) for h, r in reps.items()}


def _collect_all(hosts, user):
    return {h: remote.collect(DIAG[h], user) for h in hosts}


def run_scenario(sc, run_no):
    case = Case(ROOT / "cases", f"{sc.ID}-run{run_no}", sc.SYMPTOM)
    if os.environ.get("IDM_TEST_APPROVE") == "1":
        case.write("test-mode.txt", "approvals in this case were given by the regression runner (IDM_TEST_APPROVE=1)\n")
    hosts = getattr(sc, "HOSTS", list(sc.EXPECT))
    with case.step("reset"):
        subprocess.run([str(ROOT / "lab" / "reset.sh"), "srv1", "client2"], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
    with case.step("inject"):
        sc.inject(case.log)
    t_injected = time.monotonic()
    with case.step("collect"):
        reps = _collect_all(hosts, sc.USER)
        fl = _evaluate_all(reps)
    for h, rep in reps.items():
        case.write(f"report-before-{h}.json", rep)
    got = {h: {f.id for f in fl[h]} for h in fl}
    case.write("findings.json", {h: sorted(v) for h, v in got.items()})
    missing = {h: sorted(sc.EXPECT[h] - got.get(h, set())) for h in sc.EXPECT if sc.EXPECT[h] - got.get(h, set())}
    if missing:
        case.log(f"EXPECTED FINDINGS MISSING: {missing}"); case.write("status.txt", "DIAGNOSIS-FAILED\n")
        if hasattr(sc, "restore"):
            sc.restore(case.log)
        return case, "DIAGNOSIS-FAILED"
    no_model = os.environ.get("IDM_NO_MODEL") == "1"
    with case.step("interpret"):
        allowed = interpret.allowed_for({r["role"] for r in reps.values()})
        it = None if no_model else interpret.interpret(sc.SYMPTOM, [f for h in fl for f in fl[h]], allowed)
    expected = [rid for _, rid in sc.REPAIRS]
    if it is not None:
        it["agrees"] = (it["repair_id"] in expected) if expected else (it["repair_id"] is None and it["valid"])
        case.write("interpretation.json", it)
        case.log(f"model {it['model']}: valid={it['valid']} repair_id={it['repair_id']} shown={it['shown_repair']} "
                 f"agrees={it['agrees']} errors={it['errors'][:2]}")
    else:
        case.write("interpretation.json", {"skipped": "IDM_NO_MODEL=1"})
    for host, rid in sc.REPAIRS:
        client = reps[host]["role"] == "client"
        ctx = Ctx(host=host, role=target_role(reps[host], host), case=case,
                  collect=lambda h=host: remote.collect(DIAG[h], sc.USER), remote=remote,
                  peer=(lambda: remote.collect(DIAG["srv1"], sc.USER)) if client and "srv1" in reps else None,
                  params=dict(getattr(sc, "PARAMS", {})))
        st = run_repair(rid, ctx, approver(), REGISTRY)
        if st != "OK":
            return case, f"REPAIR-{st}"
    elapsed = time.monotonic() - t_injected
    if hasattr(sc, "restore"):
        with case.step("operator-restore"):
            sc.restore(case.log)
    with case.step("final-check"):
        final = {}
        for _ in range(12):                                      # clients may need a moment to reconnect
            final = {h: sorted(f.id for f in v) for h, v in _evaluate_all(_collect_all(hosts, sc.USER)).items()}
            if not any(final.values()):
                break
            time.sleep(5)
    case.write("findings-final.json", final)
    probe_ok = sc.final_probe(case.log) if hasattr(sc, "final_probe") else True
    status = final_status(final, probe_ok, it, no_model, elapsed if sc.REPAIRS else None,
                          getattr(sc, "CLEAR_BEFORE_S", None))
    case.log(f"inject->repairs done: {elapsed:.1f} s; status {status}")
    case.write("status.txt", status + "\n")
    return case, status


def explain(host, user, symptom):
    """Collect, evaluate, interpret, print. Never runs a repair."""
    reps = _collect_all([host] + (["srv1"] if host != "srv1" else []), user)
    fl = _evaluate_all(reps)[host]
    for f in fl:
        print(f"FINDING {f.id}: {'; '.join(f.evidence)}")
    if not fl:
        print("No findings.")
    it = interpret.interpret(symptom, fl, interpret.allowed_for({reps[host]["role"]}))
    print("\n" + ((it["response"] or {}).get("analysis") or f"(model gave no valid analysis: {it['errors'][:2]})"))
    print(f"\nSuggested repair: {it['shown_repair'] or 'none'} (model: {it['repair_id'] or 'unsure'}; "
          f"runbook default: {it['default_repair'] or 'none'})")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("collect", "findings"):
        p = sub.add_parser(c); p.add_argument("host"); p.add_argument("--user")
    p = sub.add_parser("scenario"); p.add_argument("id"); p.add_argument("--runs", type=int, default=1)
    p = sub.add_parser("explain"); p.add_argument("host"); p.add_argument("--user")
    p.add_argument("--symptom", default="(no symptom given)")
    a = ap.parse_args(argv)
    if a.cmd == "explain":
        return explain(a.host, a.user, a.symptom)
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
