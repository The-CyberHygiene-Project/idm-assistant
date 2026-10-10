"""Gate 3: the CUI scan's failures as a deviation table, each with the ISSO's decision. Exit 0 only if every failing
rule is decided 'accept'; 'fix' = not yet fixed (gate not met); undecided = gate not met; bad input = exit 2."""
import argparse
import sys
import xml.etree.ElementTree as ET

NS = {"x": "http://checklists.nist.gov/xccdf/1.2"}


def load(path):
    root = ET.parse(path).getroot()
    titles = {r.get("id"): (r.findtext("x:title", default="", namespaces=NS) or "").strip()
              for r in root.iter(f"{{{NS['x']}}}Rule")}
    tr = root.find(".//x:TestResult", NS)
    host = (tr.findtext("x:target", default=path, namespaces=NS) or path).strip()
    rows = [(rr.get("idref"), rr.get("severity", "unknown"), rr.findtext("x:result", namespaces=NS))
            for rr in tr.findall("x:rule-result", NS)]
    return host, titles, rows


def decisions(path):
    out = {}
    for n, line in enumerate(open(path), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) != 4 or f[1] not in ("accept", "fix"):
            sys.exit(f"decisions line {n}: want rule<TAB>accept|fix<TAB>who<TAB>reason")
        out[f[0]] = f[1:]
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("results", nargs="+"); ap.add_argument("--decisions", required=True)
    a = ap.parse_args()
    try:
        dec = decisions(a.decisions)
    except SystemExit as e:
        print(e, file=sys.stderr); return 2
    fails, other, titles, hosts = {}, [], {}, []
    for p in a.results:
        host, t, rows = load(p); titles.update(t); hosts.append(host)
        for rid, sev, res in rows:
            if res == "fail":
                fails.setdefault(rid, [sev, set()])[1].add(host)
            elif res in ("error", "unknown", "notchecked"):
                other.append(f"{host}: {rid} ({res})")
    out = [f"# CUI scan deviations ({', '.join(sorted(hosts))})", "", "## Failures", "",
           "| rule | severity | hosts | decision | decided by | reason | title |", "|---|---|---|---|---|---|---|"]
    problems = []
    for rid in sorted(fails):
        sev, hs = fails[rid]; d = dec.get(rid)
        if d is None:
            problems.append(f"UNDECIDED: {rid}"); d = ["UNDECIDED", "", ""]
        elif d[0] == "fix":
            problems.append(f"NOT YET FIXED: {rid}")
        out.append(f"| {rid} | {sev} | {', '.join(sorted(hs))} | {d[0]} | {d[1]} | {d[2]} | {titles.get(rid, '')} |")
    out += ["", "## Not evaluated", ""] + [f"- {o}" for o in other] + [""]
    out += [f"**Gate 3: {'MET' if not problems else 'NOT MET'}** ({len(fails)} failing rules)"] + problems
    print("\n".join(out))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
