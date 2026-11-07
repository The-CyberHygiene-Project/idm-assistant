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
    }
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
