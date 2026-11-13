# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Each host's status record for the daily review (review spec §3: every host). A timer appends one line to LOG; the
Wazuh agent (the manager, for its own host) reads it as a JSON log; manager rule 100520 stores it. Wazuh rewrites a JSON
record's top-level scalars (R1 spike), so the record's contents travel as ONE JSON-encoded string in "body"."""
import calendar
import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

LOG = "/var/log/chp-review.json"
MAX_RECORD = 60000                       # Wazuh's line limit is 64 KB
CERT_PLACES = ("etc/pki/kanidm", "etc/step-ca/certs")
ANCHORS = "etc/pki/ca-trust/source/anchors"
KEY_DIR = "etc/pki/rpm-gpg"


def _p(root, rel):
    return Path(root) / rel


def _num(path):
    try:
        s = Path(path).read_text().strip()
        return float(s) if "." in s else int(s)
    except (OSError, ValueError):
        return None


def _mtime(path):
    try:
        return int(Path(path).stat().st_mtime)
    except OSError:
        return None


def repo_id(root=Path("/")):
    """SHA-256 (12 hex) of the installed signed repo's repomd.xml: equal on hosts holding the same repo."""
    try:
        return hashlib.sha256(_p(root, "var/lib/chp/repo/repodata/repomd.xml").read_bytes()).hexdigest()[:12]
    except OSError:
        return None


def find_certs(root=Path("/")):
    out = []
    for rel in CERT_PLACES:
        d = _p(root, rel)
        if d.is_dir():
            out += sorted(p for p in d.iterdir() if p.is_file() and p.suffix in (".pem", ".crt"))
    a = _p(root, ANCHORS)
    if a.is_dir():
        out += sorted(a.glob("chp-*.crt"))
    return out


def _openssl_time(v):
    return calendar.timegm(time.strptime(" ".join(v.replace("GMT", "").split()), "%b %d %H:%M:%S %Y"))


def cert_dates(root, run):
    out = []
    for p in find_certs(root):
        r = run(["openssl", "x509", "-in", str(p), "-noout", "-startdate", "-enddate"], capture_output=True, text=True)
        kv = dict(ln.split("=", 1) for ln in (r.stdout or "").splitlines() if "=" in ln)
        try:
            nb, na = _openssl_time(kv["notBefore"]), _openssl_time(kv["notAfter"])
        except (KeyError, ValueError):
            continue
        out.append({"path": "/" + str(p.relative_to(root)), "not_before": nb, "not_after": na})
    return out


def pinned_keys(root, run):
    """Each RPM-GPG-KEY-* with its primary key's expiry (None = never), read in a private GnuPG home (no /root/.gnupg)."""
    d, out = _p(root, KEY_DIR), []
    if not d.is_dir():
        return out
    for k in sorted(d.glob("RPM-GPG-KEY-*")):
        home = tempfile.mkdtemp(prefix="chp-gpg-")
        try:
            r = run(["gpg", "--homedir", home, "--show-keys", "--with-colons", str(k)], capture_output=True, text=True)
        finally:
            shutil.rmtree(home, ignore_errors=True)
        lines = (r.stdout or "").splitlines()
        pub = next((ln.split(":") for ln in lines if ln.startswith("pub:")), None)
        fpr = next((ln.split(":")[9] for ln in lines if ln.startswith("fpr:")), None)
        if pub is None:
            continue
        exp = pub[6] if len(pub) > 6 else ""
        out.append({"file": "/" + str(k.relative_to(root)), "fpr": fpr, "expires": int(exp) if exp.isdigit() else None})
    return out


def _aide(root):
    kv = {}
    try:
        for ln in _p(root, "var/lib/chp/aide/last-result").read_text().splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                kv[k] = v.strip()
    except OSError:
        return None, None
    epoch = int(kv["EPOCH"]) if kv.get("EPOCH", "").isdigit() else None
    ok = None if "EXIT" not in kv else (kv["EXIT"] == "0" and kv.get("DB_MATCH") == "yes")
    return epoch, ok


def _rpm(run, name):
    r = run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


DOCS_CONF = "etc/chp/documents.conf"
DOCS_UNITS = ("httpd", "php-fpm", "postgresql", "nextcloud-cron.timer")
DOCS_CURSOR = "var/lib/chp/documents/review.cursor"       # when the last record was appended (counts are "since" it)
DOCS_TAIL = 2_000_000                                     # the audit log is read from its last 2 MB at most
SHARE_REFUSED = "is restricted"                           # admin_audit: "ShareAction from user X on N to Y is restricted"
CANARY_USER = "chp-canary"                                # = documents.CANARY_USER (not imported: no cycle)


def _json_file(path):
    try:
        v = json.loads(Path(path).read_text())
        return v if isinstance(v, dict) else None
    except (OSError, ValueError):
        return None


def _docs_enabled(root):
    try:
        return "ENABLED=yes" in _p(root, DOCS_CONF).read_text().splitlines()
    except OSError:
        return False


def docs_counts(root, since, now):
    """(contain refusals, share attempts, canary refusals) in NextCloud's audit log between `since` and `now`. Share attempts = shares
    refused on a controlled folder (rule 100601) or made on one (100602 would be a bug)."""
    p = _p(root, "var/log/nextcloud/audit.log")
    try:
        with open(p, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - DOCS_TAIL))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return 0, 0, 0
    cr = sa = ca = 0
    for ln in lines:
        try:
            e = json.loads(ln)
            t = calendar.timegm(time.strptime(e["time"][:19], "%Y-%m-%dT%H:%M:%S")) if "time" in e else None
        except (ValueError, KeyError, TypeError):
            continue
        if not isinstance(e, dict) or t is None or not (since < t <= now):
            continue
        msg = str(e.get("message", ""))
        if e.get("app") == "chp_foldertag" and str(e.get("event", e.get("message", ""))).startswith("chp.contain.refused"):
            cr += 1
        elif e.get("app") == "admin_audit" and msg.startswith("ShareAction from user ") and SHARE_REFUSED in msg:
            if msg.startswith(f"ShareAction from user {CANARY_USER} "):
                ca += 1                      # the nightly canary's expected refusal: not a share attempt
            else:
                sa += 1
    return cr, sa, ca


def docs_block(root, run, now):
    """The `documents` block of the server's record (design §6, §12): compact, ~300 bytes. None when documents are off."""
    if not _docs_enabled(root):
        return None
    svc = {}
    for u in DOCS_UNITS:
        r = run(["systemctl", "is-active", u], capture_output=True, text=True)
        svc[u] = (r.stdout or "").strip() or "unknown"
    cert = None
    r = run(["openssl", "x509", "-in", str(_p(root, "etc/pki/nextcloud/chain.pem")), "-noout", "-startdate", "-enddate"],
            capture_output=True, text=True)
    kv = dict(ln.split("=", 1) for ln in (r.stdout or "").splitlines() if "=" in ln)
    try:
        cert = {"nb": _openssl_time(kv["notBefore"]), "na": _openssl_time(kv["notAfter"])}
    except (KeyError, ValueError):
        pass
    bk = None
    try:
        f = _p(root, "var/lib/chp/documents/backup.status").read_text().split(None, 2)
        bk = {"st": f[0], "at": int(f[1])}
    except (OSError, IndexError, ValueError):
        pass
    chk, c = None, _json_file(_p(root, "var/lib/chp/documents/check.json"))
    if c is not None and isinstance(c.get("epoch"), (int, float)):
        kinds = {}
        for a in c.get("alerts") or []:
            k = str(a.get("key", "?")).split(":", 1)[0][:20]
            kinds[k] = kinds.get(k, 0) + 1
        can = c.get("canary") if isinstance(c.get("canary"), dict) else {}
        chk = {"at": int(c["epoch"]), "ok": bool(c.get("ok")), "kinds": kinds, "deg": bool(c.get("degraded")),
               "can": [str(can.get("public", "?"))[:24], str(can.get("internal", "?"))[:24]]}
    cur = _num(_p(root, DOCS_CURSOR))
    cr, sa, ca = docs_counts(root, cur if cur is not None else now - 600, now)
    return {"svc": svc, "cert": cert, "bk": bk, "chk": chk, "cr": cr, "sa": sa, "ca": ca}


def docs_cursor_save(root, now):
    p = _p(root, DOCS_CURSOR)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{int(now)}\n")
    except OSError:
        pass


def host_record(*, host, now, run, root=Path("/"), sys_summary=None):
    aide_check, aide_ok = _aide(root)
    body = {
        "v": 1, "host": host, "time": now,
        "versions": {"chp-site": _rpm(run, "chp-site"), "chp-security": _rpm(run, "chp-security"), "repo": repo_id(root)},
        "certs": cert_dates(root, run),
        "keys": pinned_keys(root, run),
        "scans": {"yara_recent": _num(_p(root, "var/lib/chp/yara/last-recent")),
                  "yara_full": _num(_p(root, "var/lib/chp/yara/last-full")),
                  "suricata_stats": _mtime(_p(root, "var/log/suricata/stats.log")),
                  "aide_check": aide_check, "aide_ok": aide_ok},
        "sys": sys_summary or {},
        "security_since": _mtime(_p(root, "etc/chp/security.conf")),   # when the add-on was enabled (monitor 73's rule)
    }
    docs = docs_block(root, run, now)
    if docs is not None:                      # absent (not null) when documents are off: the record is unchanged
        body["documents"] = docs
    return {"chp_review": {"v": 1, "host": host, "body": json.dumps(body, sort_keys=True, separators=(",", ":"))}}


def append(record, log=LOG):
    line = json.dumps(record, separators=(",", ":"))
    if len(line) >= MAX_RECORD:
        raise ValueError(f"review record is {len(line)} bytes (limit {MAX_RECORD})")
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    try:
        os.write(fd, (line + "\n").encode())
    finally:
        os.close(fd)
    os.chmod(log, 0o640)
