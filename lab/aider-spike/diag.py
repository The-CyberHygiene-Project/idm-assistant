"""THROWAWAY: why does aider not apply gpt-oss edits? One nss trial, then inspect the parsed edits."""
import os, sys, tempfile
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
import bench
from aider.coders import Coder
from aider.models import Model
case = next(c for c in bench.CASES if c["id"] == sys.argv[2])
d = tempfile.mkdtemp(prefix="diag-"); p = os.path.join(d, case["file"]); open(p, "w").write(case["bad"])
io = bench.GateIO([], yes=None, pretty=False, fancy_input=False)
ro = [os.path.abspath(f"{os.environ.get('REFS_DIR', 'refs')}/{case['id']}.md")] if len(sys.argv) > 3 else []
coder = Coder.create(main_model=Model(sys.argv[1]), fnames=[p], read_only_fnames=ro, io=io, auto_commits=False, use_git=False, stream=False)
coder.run(case["ask"])
raw = coder.partial_response_content
print("=== RAW repr (first 900) ===\n", repr(raw[:900]))
try:
    print("=== get_edits ===", coder.get_edits())
except Exception as e:
    print("=== get_edits ERROR ===", repr(e))
print("=== file changed:", open(p).read() != case["bad"])
