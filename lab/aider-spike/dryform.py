"""Render the decision forms for a scenario's saved proposal. DRY: every decision answered N, the host is never called."""
import json, sys, tempfile
from pathlib import Path
import live
from gate import Gate, Log

sc = sys.argv[1]
prop = json.loads((live.d(sc) / "proposal.json").read_text())
symptom = (live.d(sc) / "symptom.txt").read_text().strip()
def no_host(cmd):
    raise AssertionError("dry run must not reach the host: " + cmd)
g = Gate(live.HOST, no_host, live.briefer(sc, symptom), Log(Path(tempfile.mkdtemp()) / "dry.jsonl"), "dry", lambda: "n",
         lambda: "", print)
g.problem, g.total = symptom, len(prop["edits"]) + len(prop["commands"])
for e in prop["edits"]:
    g.ask_file(e["path"], e["new"], e["diff"], live.findings(e["path"], e["old"], e["new"]))
for c in prop["commands"]:
    g.ask(c)
