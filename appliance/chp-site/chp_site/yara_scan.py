"""YARA malware scanning (YARA spec §4). Scan only: it never changes, moves or deletes a file. Wazuh starts a
single-file scan for a file added or changed in a watched folder; a weekly timer starts a full scan. Every result
worth recording is one JSON line in LOG, which Wazuh reads (match = level 12 -> ALERT_HOOK)."""
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

RULES_DIR = "/usr/share/chp-yara-rules"
RULES = RULES_DIR + "/rules.yarc"
LOG = "/var/log/chp-yara.json"
STATE = "/var/lib/chp/yara"
WATCHED = ("/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/srv", "/data")
NEVER = ("/var/ossec", "/srv/wazuh", "/data/wazuh", "/root/chp-onboard", "/root/chp-escrow-pending",
         "/var/lib/chp/repo")
FULL_SKIP = ("/proc", "/sys", "/dev", "/run", RULES_DIR) + NEVER       # the rules file matches itself (Y1 spike)
REMOTE_FS = ("nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "9p")
MAX_BYTES = 256 * 1024 * 1024        # Task 1 measures; files above it are not scanned
TIMEOUT = 60                         # seconds, one-file scan (yara --timeout limits the whole run)
FULL_TIMEOUT = 6 * 3600              # seconds, the weekly scan (measured: about 1 minute, Y1 spike)
RATE_S = 60                          # the same file again within this many seconds: not scanned again
RECENT_S = 300                       # clients (spec §10): the timer's period; a first run looks back this far


def _under(p, roots):
    return any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)


def check_path(path, watched=WATCHED, never=NEVER, max_bytes=MAX_BYTES):
    real = os.path.realpath(path)                         # a symlink cannot reach outside the watched folders
    try:
        st = os.lstat(real)
    except OSError:
        return None, "gone"
    if not _under(real, watched) or _under(real, never):
        return None, "outside the watched folders"
    if not stat.S_ISREG(st.st_mode):
        return None, "not a regular file"                 # never opened: a FIFO would block
    if st.st_size > max_bytes:
        return None, "larger than the scan limit"
    return real, None


def _write(log, ev):
    log = Path(log)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps({"chp_yara": ev}, sort_keys=True) + "\n")
    return ev


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _yara(run, args, timeout=TIMEOUT):
    try:
        return run(["yara", "-w", "-C", RULES, f"--timeout={timeout}", *args], capture_output=True, text=True)
    except FileNotFoundError:
        return None


def _recent(state_dir, path, t):
    p = Path(state_dir) / "recent.json"
    Path(state_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        seen = json.loads(p.read_text())
    except (OSError, ValueError):
        seen = {}
    seen = {k: v for k, v in seen.items() if t - v < RATE_S}
    hit = path in seen
    if not hit:
        seen[path] = t
    p.write_text(json.dumps(seen))
    return hit


def scan_file(path, *, run, log=LOG, state_dir=STATE, now=time.time, watched=WATCHED, never=NEVER):
    real, why = check_path(path, watched, never)
    if real is None:
        return None if why == "gone" else _write(log, {"event": "skipped", "file": path, "detail": why})
    if _recent(state_dir, real, now()):
        return None
    name = os.path.basename(real)
    ext = os.path.splitext(name)[1]
    r = _yara(run, [f"--define=filename={name}", f"--define=filepath={os.path.dirname(real)}",
                    f"--define=extension={ext}", real])
    if r is None:
        return _write(log, {"event": "error", "file": real, "detail": "yara is not installed"})
    if r.returncode != 0:
        return _write(log, {"event": "error", "file": real,
                            "detail": (r.stderr.strip().splitlines() or ["yara failed"])[-1]})
    rules = sorted({ln.split(" ", 1)[0] for ln in r.stdout.splitlines() if ln.strip()})
    if not rules:
        return None
    return _write(log, {"event": "match", "file": real, "rules": ",".join(rules), "sha256": _sha256(real)})


def _remote_mounts(text):
    out = []
    for ln in text.splitlines():
        f = ln.split()
        if len(f) >= 3 and (f[2] in REMOTE_FS or f[2].startswith("fuse.")):
            out.append(f[1].replace("\\040", " "))
    return out


def full_scan(*, run, log=LOG, state_dir=STATE, now=time.time, walk_root="/", skip=FULL_SKIP, mounts_text=None,
              max_bytes=MAX_BYTES):
    t0 = now()
    if mounts_text is None:
        mounts_text = Path("/proc/mounts").read_text()
    skip = tuple(skip) + tuple(_remote_mounts(mounts_text))
    files = []
    for d, dirs, names in os.walk(walk_root):
        dirs[:] = [x for x in dirs if not _under(os.path.join(d, x), skip)]
        for n in names:
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_size <= max_bytes:
                files.append(p)
    sd = Path(state_dir); sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    lst = sd / "scan-list"
    lst.write_text("".join(p + "\n" for p in files))
    r = _yara(run, ["--scan-list", str(lst)], FULL_TIMEOUT)
    matches = errors = 0
    if r is None:
        _write(log, {"event": "error", "file": "", "detail": "yara is not installed"}); errors = 1
    else:
        hits = {}
        for ln in r.stdout.splitlines():
            rule, _, p = ln.partition(" ")
            if p:
                hits.setdefault(p, set()).add(rule)
        for p, rules in sorted(hits.items()):
            try:
                h = _sha256(p)
            except OSError:
                h = ""
            _write(log, {"event": "match", "file": p, "rules": ",".join(sorted(rules)), "sha256": h}); matches += 1
        for ln in r.stderr.splitlines():
            m = re.match(r"error scanning (.+): could not open file$", ln.strip())
            if m and not os.path.lexists(m.group(1)):
                continue                                   # a temporary file that went during the scan (Y1 spike)
            if "error" in ln.lower() and errors < 20:
                _write(log, {"event": "error", "file": "", "detail": ln.strip()}); errors += 1
    lst.unlink(missing_ok=True)
    s = {"event": "summary", "files": len(files), "matches": matches, "errors": errors, "seconds": int(now() - t0)}
    _write(log, s)
    (sd / "last-full").write_text(f"{int(now())}\n")
    return s


def recent_scan(*, run, log=LOG, state_dir=STATE, now=time.time, watched=WATCHED, never=NEVER, max_bytes=MAX_BYTES):
    """Spec §10 (clients): scan the regular files in the watched folders whose content or metadata changed since the
    previous run (a first run looks back RECENT_S). Same path rules and JSON lines as the other scans; no summary."""
    t0 = now()
    sd = Path(state_dir); sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        since = float((sd / "last-recent").read_text().strip())
    except (OSError, ValueError):
        since = t0 - RECENT_S
    files = []
    for top in watched:
        for d, dirs, names in os.walk(top):
            dirs[:] = [x for x in dirs if not _under(os.path.join(d, x), never)]   # os.walk never follows symlinks
            for n in names:
                p = os.path.join(d, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_size <= max_bytes and max(st.st_mtime, st.st_ctime) > since:
                    files.append(p)
    matches = errors = 0
    if files:
        lst = sd / "recent-list"
        lst.write_text("".join(p + "\n" for p in files))
        r = _yara(run, ["--scan-list", str(lst)], FULL_TIMEOUT)
        lst.unlink(missing_ok=True)
        if r is None:
            _write(log, {"event": "error", "file": "", "detail": "yara is not installed"}); errors = 1
        else:
            hits = {}
            for ln in r.stdout.splitlines():
                rule, _, p = ln.partition(" ")
                if p:
                    hits.setdefault(p, set()).add(rule)
            for p, rules in sorted(hits.items()):
                try:
                    h = _sha256(p)
                except OSError:
                    h = ""
                _write(log, {"event": "match", "file": p, "rules": ",".join(sorted(rules)), "sha256": h}); matches += 1
            for ln in r.stderr.splitlines():
                m = re.match(r"error scanning (.+): could not open file$", ln.strip())
                if m and not os.path.lexists(m.group(1)):
                    continue
                if "error" in ln.lower() and errors < 20:
                    _write(log, {"event": "error", "file": "", "detail": ln.strip()}); errors += 1
    (sd / "last-recent").write_text(f"{int(t0)}\n")
    return {"files": len(files), "matches": matches, "errors": errors}


def from_wazuh(text):
    try:
        msg = json.loads(text)
    except ValueError:
        return None
    if msg.get("command") != "add":
        return None
    return ((msg.get("parameters") or {}).get("alert") or {}).get("syscheck", {}).get("path")
