# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site security enable|status (security bundle spec §3-§4): Wazuh manager on the server, agents on clients,
agent keys carried on the site stick (wazuh/<host>.key). Idempotent: a second run changes nothing it already did and
never makes new agent keys."""
import os
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from . import wazuh as w
from .sitefile import SiteError

SECURITY_CONF = "etc/chp/security.conf"
KEYFILE = "etc/pki/rpm-gpg/RPM-GPG-KEY-WAZUH"
OSSEC = "var/ossec"


def _p(root, rel):
    return Path(root) / rel


def _check_key(root, run):
    k = _p(root, KEYFILE)
    if not k.exists():
        raise SiteError(f"/{KEYFILE} is missing: apply the update (chp-site 0.8.0) first")
    home = tempfile.mkdtemp(prefix="chp-gpg-")             # never creates /root/.gnupg (an AIDE change)
    try:
        r = run(["gpg", "--homedir", home, "--show-keys", "--with-colons", str(k)], capture_output=True, text=True)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    fprs = [ln.split(":")[9] for ln in r.stdout.splitlines() if ln.startswith("fpr:")]
    if not fprs or fprs[0] != w.WAZUH_FPR:
        raise SiteError(f"Wazuh key fingerprint {fprs[0] if fprs else 'unreadable'} is not the pinned {w.WAZUH_FPR}")
    run(["rpm", "--import", str(k)], check=True)


def _data_dir(root, data_is_mount, run):
    d = w.data_dir(data_is_mount)
    _p(root, d.lstrip("/")).mkdir(parents=True, exist_ok=True, mode=0o750)
    _p(root, OSSEC).mkdir(parents=True, exist_ok=True)
    fstab = _p(root, "etc/fstab")
    text = fstab.read_text()
    if not any(ln.split()[1:2] == ["/var/ossec"] for ln in text.splitlines() if ln.strip() and not ln.startswith("#")):
        fstab.write_text(text + ("" if text.endswith("\n") else "\n") + w.fstab_line(d) + "\n")
    if run(["mountpoint", "-q", "/var/ossec"]).returncode != 0:
        run(["mount", "/var/ossec"], check=True)
    return d


def _write(path, text, mode, chown=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".chp-tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    if chown:
        chown(tmp)
    os.replace(tmp, path)


def _conf(root, role, d, level=10):
    p = _p(root, SECURITY_CONF)
    old = {}
    if p.exists():
        for ln in p.read_text().splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                old[k] = v
    text = (f"ROLE={role}\nALERT_LEVEL={old.get('ALERT_LEVEL', str(level))}\n"
            f"RETENTION_DAYS={old.get('RETENTION_DAYS', '90')}\nDATA_DIR={d}\n")
    _write(p, text, 0o644)


def enable(role, host, site, hosts, *, run, stick=None, pending=None, key_file=None, root=Path("/"), data_is_mount=None,
           chown=None, record=None, api=None, sleep=time.sleep):
    """stick set: the update path (W1). stick None: first boot (W2): the server's keys go to the pending folder for
    export-client; a client's key comes from the file the installer staged (no USB at first boot)."""
    try:
        return _enable(role, host, site, hosts, stick=stick, pending=pending, key_file=key_file, run=run, root=root,
                       data_is_mount=data_is_mount, chown=chown, record=record, api=api, sleep=sleep)
    except subprocess.CalledProcessError as e:
        cmd = " ".join(e.cmd) if isinstance(e.cmd, (list, tuple)) else str(e.cmd)
        raise SiteError(f"{cmd} failed (exit {e.returncode}); see its log, fix the cause, then re-run "
                        "chp-site security enable (it is safe to repeat)") from None


def _keyline(host, text):
    line = text.strip()
    if not re.fullmatch(rf"\d{{3}} {re.escape(host)} \S+ [0-9a-f]{{64}}", line):
        raise SiteError(f"the staged Wazuh key is not {host}'s (expected 'NNN {host} <ip> <64 hex>')")
    return line + "\n"


def _enable(role, host, site, hosts, *, stick, pending, key_file, run, root, data_is_mount, chown, record, api, sleep):
    from . import audit
    if role not in ("server", "client"):
        raise SiteError(f"role must be server or client, not {role!r}")
    record = record or audit.record
    data_is_mount = os.path.ismount("/data") if data_is_mount is None else data_is_mount
    group_wazuh = chown or (lambda p: shutil.chown(p, "root", "wazuh"))
    done = []
    if stick is None and not _p(root, "var/lib/chp/repo/repodata/repomd.xml").exists():
        raise SiteError("the security add-on is on but this host has no local package repo (the ISO's repo is copied "
                        "at install; a network install does not copy it): unpack a signed repo tarball into "
                        "/var/lib/chp/repo, then run chp-site security enable")
    agent_line = None
    if role == "client":                                   # refuse before changing anything
        if stick is not None:
            src = Path(stick) / "wazuh" / f"{host}.key"
            if not src.exists():
                raise SiteError(f"no Wazuh key for {host} on the site stick (wazuh/{host}.key): "
                                "run chp-site security enable on the server first")
        else:
            src = Path(key_file) if key_file else None
            if src is None or not src.exists():
                # W2 final review I1: a retried first boot after the staged copy was used: the installed key is valid
                installed = _p(root, f"{OSSEC}/etc/client.keys")
                if installed.exists() and installed.read_text().strip():
                    src = installed
                else:
                    raise SiteError(f"no staged Wazuh key for {host} ({key_file}): reinstall with the site stick, "
                                    "after export-client on the server")
        agent_line = _keyline(host, src.read_text())
    _check_key(root, run); done.append("Wazuh signing key verified and imported")
    d = _data_dir(root, data_is_mount, run); done.append(f"data directory {d} bind-mounted at /var/ossec")
    pkg = "wazuh-manager" if role == "server" else "wazuh-agent"
    run(["dnf", "--enablerepo=chp", "install", "-y", pkg, "chp-security"], check=True); done.append(f"{pkg} installed")
    conf = _p(root, f"{OSSEC}/etc/ossec.conf")
    keys = _p(root, f"{OSSEC}/etc/client.keys")
    if role == "server":
        _write(conf, w.harden_manager(conf.read_text()), 0o640, group_wazuh)
        _write(_p(root, f"{OSSEC}/api/configuration/api.yaml"), w.API_YAML, 0o640, group_wazuh)
        if not keys.exists() or not keys.read_text().strip():
            lines = w.client_keys(hosts)
            _write(keys, "".join(v + "\n" for v in lines.values()), 0o640, group_wazuh)
            done.append(f"{len(lines)} agent keys made")
        mine = {ln.split()[1]: ln for ln in keys.read_text().splitlines() if ln.strip()}
        if stick is not None:
            dest = Path(stick) / "wazuh"
            dest.mkdir(parents=True, exist_ok=True)
        else:                                              # first boot: pending folder (0700), moved by export-client
            dest = Path(pending) / "wazuh"
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(dest, 0o700)
        for h, ln in mine.items():
            kp = dest / f"{h}.key"
            if not kp.exists() or kp.read_text().strip() != ln:
                fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(ln + "\n")
        done.append("agent keys on the site stick (wazuh/<host>.key)" if stick is not None
                    else "agent keys staged for export-client (pending folder)")
        have = run(["firewall-cmd", "--permanent", "--list-rich-rules"], capture_output=True, text=True).stdout
        new = [r for r in w.rich_rules(hosts) if r not in have.splitlines()]
        for r in new:
            run(["firewall-cmd", "-q", "--permanent", "--add-rich-rule", r], check=True)
        if new:
            run(["firewall-cmd", "-q", "--reload"], check=True)
        done.append(f"firewall: 1514/tcp from {len(w.rich_rules(hosts))} clients")
        units = ["wazuh-manager", "chp-wazuh-alerts", "chp-wazuh-retention.timer"]
    else:
        server = next(h for h in hosts if h.role == "server")
        _write(conf, w.harden_agent(conf.read_text(), server.ip), 0o640, group_wazuh)
        lio = _p(root, f"{OSSEC}/etc/local_internal_options.conf")
        cur = lio.read_text() if lio.exists() else ""
        if w.LOCAL_INTERNAL_AGENT.strip() not in cur:
            _write(lio, cur + w.LOCAL_INTERNAL_AGENT, 0o640, group_wazuh)
        _write(keys, agent_line, 0o640, group_wazuh)
        units = ["wazuh-agent"]
    _conf(root, role, d, site.get("SECURITY_ALERT_LEVEL", 10))
    run(["systemctl", "enable", "--now", *units], check=True)
    run(["systemctl", "restart", units[0]], check=True); done.append(f"started: {', '.join(units)}")
    if role == "client" and stick is None:               # W2: let the agent's first sync land before AIDE's baseline
        synced = _p(root, f"{OSSEC}/etc/shared/merged.mg")
        for _ in range(40):
            if synced.exists():
                break
            sleep(3)
        done.append("agent's first sync from the manager received" if synced.exists()
                    else "agent not synced yet (the manager was not reachable within 2 minutes; AIDE may report "
                         "/var/ossec/etc/shared once)")
    if role == "client" and stick is None and key_file and Path(key_file).exists():
        # shredded only now that the agent runs (W2 final review I1): a failed step above leaves it for the retry
        if run(["shred", "-u", str(key_file)]).returncode != 0 or Path(key_file).exists():
            Path(key_file).unlink(missing_ok=True)
    if role == "server":
        done.append(_lock_api(api or _https_api, sleep))
    record("security enable", {"role": role, "host": host}, after=True)
    return done


API_USERS = ((1, "wazuh"), (2, "wazuh-wui"))           # Wazuh's two reserved API users (lab: ids 1 and 2)


def _https_api(method, path, user=None, token=None, body=None):
    """One call to the local Wazuh API (127.0.0.1:55000, self-signed TLS). Credentials travel in the request, never on a
    command line. Returns (HTTP status, text); status 0 = not reachable."""
    import base64
    import ssl
    import urllib.error
    import urllib.request
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request("https://127.0.0.1:55000" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if user:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{user[0]}:{user[1]}".encode()).decode())
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError):
        return 0, ""


def _lock_api(api, sleep, wait=90):
    """Final review C1: replace the API's default logins (wazuh:wazuh, wazuh-wui:wazuh-wui) with random passwords that
    are never stored or printed. Nothing in the appliance uses the API. Idempotent: a refused default login = already
    locked."""
    locked, refused = 0, 0
    for uid, name in API_USERS:
        for _ in range(wait // 3):
            code, tok = api("POST", "/security/user/authenticate?raw=true", user=(name, name))
            if code:
                break
            sleep(3)                                     # the API starts a little after the manager
        else:
            raise SiteError("the Wazuh API did not answer on 127.0.0.1:55000; re-run chp-site security enable")
        if code == 401:
            refused += 1
            continue
        if code != 200:
            raise SiteError(f"the Wazuh API answered {code} to a login; re-run chp-site security enable")
        c, _ = api("PUT", f"/security/users/{uid}", token=tok.strip(), body={"password": w.api_password()})
        if c != 200:
            raise SiteError(f"could not change the Wazuh API password for {name} (HTTP {c}); re-run chp-site security enable")
        locked += 1
    if locked:
        return f"Wazuh API logins locked ({locked} default passwords replaced with random ones, not stored)"
    return "Wazuh API logins already locked (default passwords refused)"


def status(root, run):
    p = _p(root, SECURITY_CONF)
    if not p.exists():
        return "security add-on: not enabled on this host (chp-site security enable)"
    kv = dict(ln.split("=", 1) for ln in p.read_text().splitlines() if "=" in ln)
    units = ["wazuh-manager", "chp-wazuh-alerts"] if kv.get("ROLE") == "server" else ["wazuh-agent"]
    rows = [f"role: {kv.get('ROLE')}  alert level: {kv.get('ALERT_LEVEL')}  retention: {kv.get('RETENTION_DAYS')} days  "
            f"data: {kv.get('DATA_DIR')}"]
    for u in units:
        st = run(["systemctl", "is-active", u], capture_output=True, text=True).stdout.strip() or "unknown"
        rows.append(f"{u}: {st}")
    return "\n".join(rows)
