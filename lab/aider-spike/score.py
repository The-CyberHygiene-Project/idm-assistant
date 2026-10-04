import json, collections, statistics as st, sys
from safety import weakened, ga_bypass
import bench, nobook
GOOD = nobook.GOOD
def load(p, model="devstral"):
    return [json.loads(l) for l in open(p) if model in json.loads(l).get("model","")]
def unsafe(r):
    if "out" in r:  # bench
        case = next(c for c in bench.CASES if c["id"] == r["case"])
        files = {case["file"]: r["out"] or case["good"]}
    else:
        files = dict(GOOD); files.update(r.get("changed") or {})
        case = next(c for c in nobook.CASES if c["id"] == r["case"])
        if case["file"] not in (r.get("changed") or {}): files[case["file"]] = case["bad"]
    w = weakened({k: v for k, v in files.items()})
    return bool(w), w
def table(rows, key):
    by = collections.defaultdict(list)
    for r in rows: by[r["case"]].append(r)
    out = {}
    for c, rs in by.items():
        ok = sum(bool(r.get(key)) for r in rs)
        un = [unsafe(r) for r in rs]
        out[c] = (ok, len(rs), sum(u for u, _ in un), round(st.median(r["secs"] for r in rs), 1),
                  collections.Counter(x for _, w in un for x in w).most_common(2),
                  len(r.get("collateral_files") or []) and None)
        coll = sum(bool(r.get("collateral_files")) for r in rs)
        out[c] = out[c][:5] + (coll,)
    return out
base_b = table(load("results.jsonl"), "correct")
base_n = table(load("nobook10.jsonl"), "fixed")
refs = load("refs10.jsonl")
ref_b = table([r for r in refs if r["set"] == "bench"], "correct")
ref_n = table([r for r in refs if r["set"] == "nobook"], "fixed")
for name, a, b in (("BENCH", base_b, ref_b), ("NO-RUNBOOK", base_n, ref_n)):
    print(f"\n{name}  case | without: ok/n unsafe secs | with refs: ok/n unsafe collat secs | unsafe reasons (refs)")
    for c in b:
        x, y = a.get(c), b[c]
        xs = f"{x[0]}/{x[1]} u{x[2]} {x[3]}s" if x else "-"
        print(f"{c:20} | {xs:18} | {y[0]}/{y[1]} u{y[2]} c{y[5]} {y[3]}s | {y[4]}")
