# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site security enable|status (security bundle spec §3-§4): Wazuh manager on the server, agents on clients,
agent keys carried on the site stick (wazuh/<host>.key). Idempotent: a second run changes nothing it already did and
never makes new agent keys."""
import os
import shutil
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
    r = run(["gpg", "--show-keys", "--with-colons", str(k)], capture_output=True, text=True)
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


def _conf(root, role, d):
    p = _p(root, SECURITY_CONF)
    old = {}
    if p.exists():
        for ln in p.read_text().splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                old[k] = v
    text = (f"ROLE={role}\nALERT_LEVEL={old.get('ALERT_LEVEL', '10')}\n"
            f"RETENTION_DAYS={old.get('RETENTION_DAYS', '90')}\nDATA_DIR={d}\n")
    _write(p, text, 0o644)


def enable(role, host, site, hosts, *, stick, run, root=Path("/"), data_is_mount=None, chown=None, record=None):
    from . import audit
    if role not in ("server", "client"):
        raise SiteError(f"role must be server or client, not {role!r}")
    record = record or audit.record
    data_is_mount = os.path.ismount("/data") if data_is_mount is None else data_is_mount
    group_wazuh = chown or (lambda p: shutil.chown(p, "root", "wazuh"))
    done = []
    if role == "client":                                   # refuse before changing anything
        keyline = (Path(stick) / "wazuh" / f"{host}.key")
        if not keyline.exists():
            raise SiteError(f"no Wazuh key for {host} on the site stick (wazuh/{host}.key): "
                            "run chp-site security enable on the server first")
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
        for h, ln in mine.items():
            kp = Path(stick) / "wazuh" / f"{h}.key"
            kp.parent.mkdir(parents=True, exist_ok=True)
            if not kp.exists() or kp.read_text().strip() != ln:
                kp.write_text(ln + "\n")
        done.append("agent keys on the site stick (wazuh/<host>.key)")
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
        _write(keys, (Path(stick) / "wazuh" / f"{host}.key").read_text(), 0o640, group_wazuh)
        units = ["wazuh-agent"]
    _conf(root, role, d)
    run(["systemctl", "enable", "--now", *units], check=True)
    run(["systemctl", "restart", units[0]], check=True); done.append(f"started: {', '.join(units)}")
    record("security enable", {"role": role, "host": host}, after=True)
    return done


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
