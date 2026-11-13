"""proto/docs_ledger.py (Task 2 SPIKE, throwaway; stdlib only, Python 3.9; RUNS ON THE SERVER AS ROOT): the central
approval ledger, modelled on appliance/chp-site/chp_site/review_ledger.py (one JSON line per entry, each carrying the
SHA-256 of the previous line, flock, a head witness, export of the head to the site stick, verify against the stick).

Requests arrive by one of two routes and this program alone appends:
  process   route L1: requests the NextCloud app chp_ledger dropped in SPOOL (identity = the user NextCloud authenticated);
            run by chp-docs-ledger.path/.service when a request lands. A result goes to OUT/<id>.json for the app.
  drop      route L2: request files users uploaded into the "Approvals" team folder; identity = the uploader that
            NextCloud's admin_audit log names for that file id (the file's own content is never trusted for it).
  verify | export STICKDIR | verify-heads STICKDIR | show

Rules (design 4): approve = a listed approver, never the document's author (the user of its latest checkout);
override = the ISSO approving their own document with a reason, only when no other approver exists (flagged, alerted);
publish = needs an approval of this exact sha256 after the latest checkout, by someone other than the publisher."""
import fcntl
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(os.environ.get("CHP_DOCS_BASE", "/var/lib/chp-docs"))
LEDGER, HEAD = BASE / "ledger" / "ledger.jsonl", BASE / "ledger" / "ledger.head"
SPOOL, OUT = BASE / "spool", BASE / "out"
APPROVERS = ["lab03", "lab04"]          # spike stand-ins for the new site keys (Kanidm account names)
ISSO = "lab04"
GENESIS = "0" * 64
FIELDS = ("seq", "time", "action", "user", "auth", "kanidm", "route", "fileid", "path", "sha256", "notes", "reason",
          "request", "flag", "prev")
DROP_DIR = "/data/nextcloud/data/__groupfolders/{gid}/files"
AUDIT = "/var/log/nextcloud/audit.log"


class LedgerError(Exception):
    pass


def entry_hash(line):
    return hashlib.sha256(line.rstrip("\n").encode()).hexdigest()


def _lines():
    if not LEDGER.exists():
        return []
    text = LEDGER.read_text()
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    elif lines:
        raise LedgerError(f"line {len(lines)} is incomplete (an interrupted write?)")
    return lines


def read():
    out, prev = [], GENESIS
    for n, ln in enumerate(_lines(), 1):
        e = json.loads(ln)
        if set(e) != set(FIELDS):
            raise LedgerError(f"line {n} has the wrong fields")
        if e["prev"] != prev:
            raise LedgerError(f"entry {n} does not follow entry {n - 1} (the chain is broken there)")
        out.append(e)
        prev = entry_hash(ln)
    if HEAD.exists():
        count, h = HEAD.read_text().split()[:2]
        lines = _lines()
        if len(lines) < int(count) or (int(count) and entry_hash(lines[int(count) - 1]) != h):
            raise LedgerError(f"the ledger is shorter than its recorded head ({count} entries)")
    return out


def head():
    lines = _lines()
    return len(lines), (entry_hash(lines[-1]) if lines else GENESIS)


def decide(entries, r):
    """None = allowed, else the reason for refusing. r: the request (identity already authenticated)."""
    mine = [e for e in entries if e["fileid"] == r["fileid"]]
    co = [e for e in mine if e["action"] == "checkout"]
    author = co[-1]["user"] if co else None
    since = mine[mine.index(co[-1]) + 1:] if co else mine
    a = r["action"]
    if a == "checkout":
        return None
    if a == "approve":
        if author is None:
            return "no checkout recorded for this document"
        if r["user"] == author:
            return f"{r['user']} is the author (the user who checked it out); an approver must be someone else"
        if r["user"] not in APPROVERS:
            return f"{r['user']} is not an approver"
        return None
    if a == "override":
        if r["user"] != ISSO:
            return "only the ISSO may override"
        if not r["reason"].strip():
            return "an override needs a reason"
        others = [x for x in APPROVERS if x != ISSO]
        if others:
            return f"not a one-person site: other approver(s) exist ({', '.join(others)})"
        return None
    if a == "publish":
        ok = [e for e in since if e["action"] in ("approve", "override") and e["sha256"] == r["sha256"]
              and (e["user"] != r["user"] or e["action"] == "override")]
        if not ok:
            return "no approval of this exact file (sha256) since the checkout, by someone other than the publisher"
        return None
    return "unknown action"


def append(r, route):
    LEDGER.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(LEDGER, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        entries = read()
        why = decide(entries, r)
        if why:
            return None, why
        n, prev = head()
        e = {"seq": n + 1, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": r["action"],
             "user": r["user"], "auth": r["auth"], "kanidm": r.get("kanidm"), "route": route, "fileid": r["fileid"],
             "path": r["path"], "sha256": r["sha256"], "notes": r.get("notes", ""), "reason": r.get("reason", ""),
             "request": r["id"], "flag": "OVERRIDE: alert + next daily review" if r["action"] == "override" else "",
             "prev": prev}
        line = json.dumps(e, sort_keys=True, separators=(",", ":"))
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
        tmp = HEAD.with_name("ledger.head.tmp")
        hf = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(hf, f"{e['seq']} {entry_hash(line)}\n".encode()); os.close(hf)
        os.replace(tmp, HEAD)
        return e, None
    finally:
        os.close(fd)


def _result(r, e, why):
    res = {"id": r["id"], "user": r["user"], "ok": e is not None, "reason": why,
           "seq": e["seq"] if e else None, "entry": entry_hash(_lines()[-1]) if e else None}
    OUT.mkdir(exist_ok=True)
    tmp = OUT / f"{r['id']}.tmp"
    tmp.write_text(json.dumps(res))
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT / f"{r['id']}.json")
    return res


def process():
    """Route L1: every request in the spool, oldest first."""
    for p in sorted(SPOOL.glob("*.json"), key=lambda x: x.stat().st_mtime):
        try:
            r = json.loads(p.read_text())
            if not re.fullmatch(r"[0-9a-f]{32}", r.get("id", "")) or p.stem != r["id"]:
                raise ValueError("bad id")
        except (ValueError, KeyError) as err:
            print(f"spool {p.name}: refused ({err})"); p.unlink(); continue
        e, why = append(r, "L1-ocs")
        res = _result(r, e, why)
        print(f"L1 {r['action']} by {r['user']} ({r['auth']}) fileid {r['fileid']}: "
              f"{'APPENDED seq ' + str(res['seq']) if e else 'REFUSED: ' + why}")
        if e and r["action"] == "override":
            print("  ALERT (ALERT_HOOK in the product): ISSO override recorded")
        p.unlink()


def uploader(fileid, name):
    """Route L2: who uploaded this file, according to NextCloud's own audit log (the last 'written to' or 'created'
    record for this file id under Approvals/)."""
    who = None
    pat = re.compile(r'File with id "%d" (?:written to|created)[^"]*: "/([^/]+)/files/Approvals/%s"' % (fileid, re.escape(name)))
    with open(AUDIT) as f:
        for ln in f:
            if f'id \\"{fileid}\\"' not in ln:          # the raw JSON line escapes the quotes (logs/58)
                continue
            try:
                d = json.loads(ln)
            except ValueError:
                continue
            m = pat.search(d.get("message", ""))
            if m and d.get("user") == m.group(1):
                who = d["user"]
    return who


def drop(gid):
    folder = DROP_DIR.format(gid=gid)
    for p in sorted(glob.glob(os.path.join(folder, "*.json"))):
        name = os.path.basename(p)
        q = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-At", "nextcloud", "-c",
                            "select f.fileid from oc_filecache f join oc_group_folders g on g.storage_id = f.storage "
                            f"where g.folder_id = {int(gid)} and f.path = 'files/{name}'"],
                           capture_output=True, text=True).stdout.strip()
        fileid = int(q) if q.isdigit() else None
        try:
            body = json.load(open(p))
        except ValueError:
            body = {}
        who = uploader(fileid, name) if fileid else None
        claimed = body.get("user")
        r = {"id": hashlib.sha256(name.encode()).hexdigest()[:32],
             "action": body.get("action"), "user": who, "auth": "nextcloud audit log", "kanidm": None,
             "fileid": body.get("fileid"), "path": body.get("path", ""), "sha256": body.get("sha256", ""),
             "notes": body.get("notes", ""), "reason": body.get("reason", "")}
        if not who:
            print(f"L2 {name}: REFUSED: no audit record names its uploader (file id {fileid})")
        else:
            e, why = append(r, "L2-drop")
            print(f"L2 {r['action']} by {who} (claimed in the file: {claimed!r}) fileid {r['fileid']}: "
                  f"{'APPENDED seq ' + str(e['seq']) if e else 'REFUSED: ' + why}")
        os.unlink(p)
    subprocess.run(["/usr/bin/occ", "groupfolders:scan", str(gid)],
                   capture_output=True)


def export(stick):
    out = Path(stick) / "docs-ledger"
    out.mkdir(parents=True, exist_ok=True)
    if LEDGER.exists():
        (out / "ledger.jsonl").write_bytes(LEDGER.read_bytes())
    try:
        read(); status = "OK: chain and head match\n"
    except LedgerError as err:
        status = f"PROBLEM: {err}\n"
    (out / "verify.txt").write_text(status)
    n, h = head()
    with open(out / "heads.txt", "a") as f:
        f.write(f"{n} {h} {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n")
    print(f"exported to {out}: head {n} {h[:16]}...; {status.strip()}")


def verify_heads(stick):
    lines, problems = _lines(), []
    for ln in (Path(stick) / "docs-ledger" / "heads.txt").read_text().splitlines():
        n, h, t = ln.split()[:3]
        n = int(n)
        if n > len(lines):
            problems.append(f"head at {t}: the stick saw {n} entries; the server has {len(lines)} (entries removed)")
        elif n and entry_hash(lines[n - 1]) != h:
            problems.append(f"head at {t}: entry {n} is not the one the stick recorded (the ledger was rewritten)")
    print("verify-heads:", "OK" if not problems else "PROBLEMS: " + "; ".join(problems))
    return problems


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        if a[:1] == ["process"]:
            process()
        elif a[:1] == ["drop"]:
            drop(a[1])
        elif a[:1] == ["verify"]:
            print(f"verify: OK, {len(read())} entries, head {head()[0]} {head()[1][:16]}...")
        elif a[:1] == ["export"]:
            export(a[1])
        elif a[:1] == ["verify-heads"]:
            sys.exit(1 if verify_heads(a[1]) else 0)
        elif a[:1] == ["show"]:
            for e in read():
                k = e["kanidm"] or {}
                print(f"{e['seq']:3} {e['time']} {e['route']:8} {e['action']:8} {e['user']:6} auth={e['auth']:<14} "
                      f"kanidm_sub={str(k.get('sub'))[:8]} file {e['fileid']} {e['sha256'][:12]} {e['flag']}")
        else:
            print(__doc__); sys.exit(2)
    except LedgerError as err:
        print(f"LEDGER PROBLEM: {err}"); sys.exit(1)
