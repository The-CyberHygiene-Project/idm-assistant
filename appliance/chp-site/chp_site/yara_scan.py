"""YARA malware scanning (YARA spec §4, §10). Scan only: it never changes, moves or deletes a file. On every host a
5-minute timer scans files changed in the watched folders and a weekly timer scans every local file system. Every
result worth recording is one JSON line in LOG, which Wazuh reads (match = level 12 -> ALERT_HOOK). File names are
handled as bytes: a name need not be UTF-8, and a name with a line break is never put in a scan list."""
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
WATCHED = ("/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/run/user", "/srv", "/data")
NEVER = ("/var/ossec", "/srv/wazuh", "/data/wazuh", "/root/chp-onboard", "/root/chp-escrow-pending",
         "/var/lib/chp/repo")
FULL_SKIP = ("/proc", "/sys", "/dev", "/run", RULES_DIR) + NEVER       # the rules file matches itself (Y1 spike)
REMOTE_FS = ("nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "9p")
MAX_BYTES = 256 * 1024 * 1024        # Task 1 measures; files above it are not scanned
TIMEOUT = 60                         # seconds, one-file scan (yara --timeout limits the whole run)
FULL_TIMEOUT = 6 * 3600              # seconds, the weekly scan (measured: about 1 minute, Y1 spike)
RATE_S = 60                          # the same file again within this many seconds: not scanned again
RECENT_S = 300                       # spec §10: the timer's period; a first run looks back this far
RECENT_TIMEOUT = 20 * 60             # seconds, one 5-minute run (the unit itself stops after 30 min)


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
    try:                                                   # bytes: file names need not be UTF-8
        return run(["yara", "-w", "-C", RULES, f"--timeout={timeout}", *args], capture_output=True)
    except FileNotFoundError:
        return None


def _text(data):
    """Lines of yara's output; undecodable bytes in a file name are kept (as surrogates), never an exception."""
    if isinstance(data, bytes):
        return [os.fsdecode(ln) for ln in data.splitlines()]
    return (data or "").splitlines()


def _hits(stdout):
    hits = {}
    for ln in _text(stdout):
        rule, _, p = ln.partition(" ")
        if p:
            hits.setdefault(p, set()).add(rule)
    return hits


def _write_list(path, files):
    Path(path).write_bytes(b"".join(os.fsencode(p) + b"\n" for p in files))


def _scan_files(run, files, timeout, log, sd, name):
    """Scan FILES: names without a line break through one --scan-list, any others one by one (a line break would split
    the list entry). Returns (matches, errors, ok); ok is False when yara could not do its job."""
    plain = [p for p in files if "\n" not in p and "\r" not in p]
    runs = []
    if plain:
        lst = sd / name
        _write_list(lst, plain)
        try:
            runs.append((None, _yara(run, ["--scan-list", str(lst)], timeout)))
        finally:
            lst.unlink(missing_ok=True)
    for p in files:
        if "\n" in p or "\r" in p:
            runs.append((p, _yara(run, [p], timeout)))
    matches = errors = 0
    ok = True
    for known, r in runs:
        if r is None:
            _write(log, {"event": "error", "file": "", "detail": "yara is not installed"}); return matches, errors + 1, False
        if known is None:
            hits = _hits(r.stdout)
        else:                                              # one file through argv: every rule line names it
            rules = {ln.split(" ", 1)[0] for ln in _text(r.stdout) if " " in ln}
            hits = {known: rules} if rules else {}
        for p, rules in sorted(hits.items()):
            try:
                h = _sha256(p)
            except OSError:
                h = ""
            _write(log, {"event": "match", "file": p, "rules": ",".join(sorted(rules)), "sha256": h}); matches += 1
        for ln in _text(r.stderr):
            m = re.match(r"error scanning (.+): could not open file$", ln.strip())
            if m and not os.path.lexists(m.group(1)):
                continue                                   # a temporary file that went during the scan (Y1 spike)
            if "error" in ln.lower() and errors < 20:
                _write(log, {"event": "error", "file": "", "detail": ln.strip()}); errors += 1
        if r.returncode != 0:
            ok = False
            _write(log, {"event": "error", "file": "", "detail": f"yara exit {r.returncode}"}); errors += 1
    return matches, errors, ok


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
                            "detail": ([ln for ln in _text(r.stderr) if ln.strip()] or [f"yara exit {r.returncode}"])[-1]})
    rules = sorted({ln.split(" ", 1)[0] for ln in _text(r.stdout) if ln.strip()})
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


def _walk(top, skip, max_bytes, since=None):
    files = []
    for d, dirs, names in os.walk(top):                    # os.walk never follows symlinks
        dirs[:] = [n for n in dirs if not _under(os.path.join(d, n), skip)]
        for n in names:
            p = os.path.join(d, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_size <= max_bytes and \
                    (since is None or max(st.st_mtime, st.st_ctime) > since):
                files.append(p)
    return files


def full_scan(*, run, log=LOG, state_dir=STATE, now=time.time, walk_root="/", skip=FULL_SKIP, mounts_text=None,
              max_bytes=MAX_BYTES):
    t0 = now()
    sd = Path(state_dir); sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    files, matches, errors, ok = [], 0, 0, False
    try:
        if mounts_text is None:
            mounts_text = Path("/proc/mounts").read_text()
        files = _walk(walk_root, tuple(skip) + tuple(_remote_mounts(mounts_text)), max_bytes)
        matches, errors, ok = _scan_files(run, files, FULL_TIMEOUT, log, sd, "scan-list")
    except Exception as e:                                 # one line, never a dead timer (final review C1)
        _write(log, {"event": "error", "file": "", "detail": f"weekly scan failed: {e!r}"}); errors += 1
    s = {"event": "summary", "files": len(files), "matches": matches, "errors": errors, "seconds": int(now() - t0)}
    _write(log, s)
    if ok:                                                 # only a scan that ran counts (final review I1)
        (sd / "last-full").write_text(f"{int(now())}\n")
    return s


def recent_scan(*, run, log=LOG, state_dir=STATE, now=time.time, watched=WATCHED, never=NEVER, max_bytes=MAX_BYTES):
    """Spec §10: scan the regular files in the watched folders whose content or metadata changed since the previous
    successful run (a first run looks back RECENT_S). A failed run leaves the mark, so its files are tried again."""
    t0 = now()
    sd = Path(state_dir); sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    files, matches, errors, ok = [], 0, 0, False
    try:
        try:
            since = float((sd / "last-recent").read_text().strip())
        except (OSError, ValueError):
            since = t0 - RECENT_S
        for top in watched:
            files += _walk(top, never, max_bytes, since)
        matches, errors, ok = _scan_files(run, files, RECENT_TIMEOUT, log, sd, "recent-list") if files else (0, 0, True)
    except Exception as e:                                 # final review C1
        _write(log, {"event": "error", "file": "", "detail": f"5-minute scan failed: {e!r}"}); errors += 1; ok = False
    if ok:
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
