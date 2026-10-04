"""aider spike — the same cases WITH reference passages from the sysadmin RAG library (THROWAWAY).
Retrieval = (a) passages from the reference documents routed by the file being edited + (b) top passages from the whole
library by meaning. The passages are given to aider as a READ-ONLY file. Retrieval runs OUTSIDE the sandbox (it needs the
library + LM Studio embeddings, both local); aider itself still runs only through run-aider.sh.
Usage:  ~/rag-library/venv/bin/python withrefs.py prepare        -> refs/<case>.md for every bench + no-runbook case
        run-aider.sh withrefs.py run MODEL TRIALS OUT.jsonl"""
import json
import os
import sys

ROUTE = {  # file being edited -> reference sources (exact names in the sysadmin library)
    "unixd": ["kanidm-1.11.2_unixd_configuration_reference.txt"],
    "kanidm-config": ["kanidm-1.11.2_client_configuration_reference.txt"],
    "config": ["kanidm-1.11.2_client_configuration_reference.txt"],
    "system-auth": ["rocky9.8_man_pam.conf.5.txt", "rocky9.8_man_pam_unix.8.txt", "rocky9.8_man_pam_localuser.8.txt",
                    "google-authenticator-1.09_pam_README.md"],
    "nsswitch.conf": ["rocky9.8_man_nsswitch.conf.5.txt"],
    "10-chp.conf": ["rocky9.8_man_sshd_config.5.txt"],
    "60-chp-admins": ["rocky9.8_man_sudoers.5.txt"],
}


def prepare():
    sys.path.insert(0, os.path.expanduser("~/rag-library"))
    os.environ["RAG_PROFILE"] = "sysadmin"
    import rag_utils
    from bench import CASES as B
    from nobook import CASES as N
    col = rag_utils.get_collection()
    os.makedirs("refs", exist_ok=True)
    for c in list(B) + list(N):
        q = c["ask"]
        emb = rag_utils.embed_query(q)
        routed = col.query(query_embeddings=[emb], n_results=3,
                           where={"source": {"$in": ROUTE[c["file"]]}}, include=["documents", "metadatas"])
        general = rag_utils.retrieve(q, top_k=3)
        parts = [f"### {m['source']}\n{d}" for d, m in zip(routed["documents"][0], routed["metadatas"][0])]
        parts += [f"### {g['source']}\n{g['text']}" for g in general]
        open(f"refs/{c['id']}.md", "w").write("# Reference passages (from the local system-administration library)\n\n"
                                              + "\n\n".join(parts) + "\n")
        print(c["id"], [m["source"] for m in routed["metadatas"][0]], [g["source"] for g in general])


def run(model_name, trials, out):
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    import bench
    import nobook
    from aider.coders import Coder
    orig_create = Coder.create

    def make(case):
        ref = os.path.abspath(f"{os.environ.get('REFS_DIR', 'refs')}/{case['id']}.md")

        def create(*a, **kw):
            kw["read_only_fnames"] = [ref]
            return orig_create(*a, **kw)
        return create

    from aider.models import Model
    model = Model(model_name)
    with open(out, "a") as f:
        for n in range(int(trials)):
            for mod, cases in ((bench, bench.CASES), (nobook, nobook.CASES)):
                for case in cases:
                    Coder.create = make(case)
                    try:
                        r = mod.trial(model, case)
                    finally:
                        Coder.create = orig_create
                    r.update(model=model_name, trial=n, set="bench" if mod is bench else "nobook", refs=True)
                    f.write(json.dumps(r) + "\n"); f.flush()
                    print(f"t{n} {case['id']:20} ok={r.get('correct', r.get('fixed'))} {r['secs']}s", flush=True)


if __name__ == "__main__":
    prepare() if sys.argv[1] == "prepare" else run(*sys.argv[2:5])
