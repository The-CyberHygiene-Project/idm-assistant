# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site documents enable|status (ISO 0.7.0 design §2, §3, §6, §12; Plan 2 Task 5): NextCloud as the site's local,
offline, Kanidm-signed-in CUI store on the CHP server. The product port of lab/docs-spike setup.sh, folders.sh and
kanidm.sh. Every command goes through an injected runner (`run` for the host, `occ` for NextCloud, a `Kanidm` for the
identity server), so the whole sequence is testable. Idempotent: a second run creates nothing (no folder, tag, group,
OIDC client, user, database or role) and rewrites only files whose content changed."""
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import documents_render as dr
from . import wazuh as w
from .hosts import server_of
from .sitefile import SiteError

CONF = "etc/chp/documents.conf"
LAN_INC = "etc/httpd/conf.d/chp-nextcloud-lan.inc"
EGRESS_ADDR = "etc/chp/nextcloud-egress-addr.nft"
PGDATA = "var/lib/pgsql/data"
DATA = "/data/nextcloud"
OIDC_SECRET = "/etc/nextcloud/oidc-secret"
CONFIG_PHP = "/etc/nextcloud/config.php"
SITE_ROOT_CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"
CERT = "etc/pki/nextcloud/chain.pem"
FSMARK_PENDING = "var/lib/chp/fapolicyd-restart-pending"
MARK = "var/lib/chp/documents/restart-pending"           # units still to restart (a failed run leaves them here)
PORT = 8443
ADMIN = "ncadmin"
CLIENT = "nextcloud"

# Team folders (design §3): the first three are controlled (cui-users only, share OFF, contained, reviewers read-only).
CONTROLLED = ("CUI", "FCI", "Archive")
OPEN = ("Operations", "Internal", "Public")
FOLDER_TAG = {"CUI": "CUI", "FCI": "FCI", "Archive": "CUI"}    # Archive holds CUI (Task 3 review)
GROUPS_NC = ("cui-users", "doc-reviewers", "chp-users")
REVIEWER_ACL = ["+read", "-write", "-create", "-delete", "-share"]

PACKAGES = ("nextcloud-chp", "chp-documents")
MTAS = ("postfix", "sendmail", "exim", "opensmtpd")
APPS_ON = ("admin_audit", "groupfolders", "files_accesscontrol", "user_oidc", "chp_foldertag", "systemtags",
           "password_policy", "bruteforcesettings", "files_downloadlimit", "workflowengine", "viewer", "files_pdfviewer")
# editors (design §3: view and download only), outbound features, federation, extras
APPS_OFF = ("text", "richdocuments", "richdocumentscode", "onlyoffice", "whiteboard", "files_texteditor",
            "firstrunwizard", "recommendations", "survey_client", "nextcloud_announcements", "updatenotification",
            "federation", "sharebymail", "weather_status", "support", "app_api", "webhook_listeners", "files_external",
            "contactsinteraction", "dashboard", "circles", "photos", "related_resources", "user_status",
            "files_reminders", "privacy", "suspicious_login", "twofactor_nextcloud_notification", "appstore")
UNITS = ("php-fpm", "httpd", "nextcloud-cron.timer", "chp-nextcloud-backup.timer", "chp-nextcloud-cert-renew.timer")
STATUS_UNITS = ("chp-nextcloud-egress.service", "postgresql") + UNITS


# md5('chp'), what FolderGuardListener compares SELECT MD5('chp') with. A constant: hashlib's MD5 may be refused
# under FIPS (tests check it equals hashlib's value).
MD5_CHP = "59fcb956ca6369b0e24a225d7e26c795"


def _system(fqdn):
    """occ config:system:set (keys, value, type). design §2-§3 + the spike's hardening (setup.sh config)."""
    url = f"https://{fqdn}:{PORT}"
    b = lambda k, v: ([k], v, "boolean")
    return [(["trusted_domains", "0"], fqdn, None), (["overwrite.cli.url"], url, None),
            (["overwritehost"], f"{fqdn}:{PORT}", None), (["overwriteprotocol"], "https", None),
            # no internet: the switches NextCloud has, and every feature that would call out
            b("has_internet_connection", "false"), b("appstoreenabled", "false"), b("updatechecker", "false"),
            b("upgrade.disable-web", "true"), b("check_for_working_wellknown_setup", "false"),
            (["lookup_server"], "", None), b("gs.enabled", "false"), b("knowledgebaseenabled", "false"),
            b("reference_opengraph", "false"), b("enable_previews", "false"),
            (["skeletondirectory"], "", None), (["templatedirectory"], "", None),
            (["mail_smtpmode"], "null", None),                     # mail OFF (no MTA either: checked before)
            (["memcache.local"], "\\OC\\Memcache\\APCu", None), b("filelocking.enabled", "true"),
            b("auth.bruteforce.protection.enabled", "true"),
            (["session_lifetime"], "900", "integer"), b("session_keepalive", "false"),
            (["remember_login_cookie_lifetime"], "0", "integer"), b("auto_logout", "true"),
            b("sharing.enable_share_accept", "false"),
            (["log_type"], "file", None), (["logfile"], "/var/log/nextcloud/nextcloud.log", None),
            (["loglevel"], "2", "integer"), (["log_type_audit"], "file", None),
            (["logfile_audit"], w.NC_AUDIT, None),
            (["log.condition", "apps", "0"], "admin_audit", None),   # else loglevel 2 drops every audit line (level 1)
            (["logtimezone"], "UTC", None), (["default_phone_region"], "US", None),
            (["maintenance_window_start"], "8", "integer"),
            b("allow_local_remote_servers", "true")]                   # Kanidm is a LAN address; egress limits where


SHARING = [("core", "shareapi_allow_resharing", "no"), ("core", "shareapi_enforce_links_password", "yes"),
           ("core", "shareapi_default_expire_date", "yes"), ("core", "shareapi_enforce_expire_date", "yes"),
           ("core", "shareapi_expire_after_n_days", "7"), ("core", "shareapi_allow_public_upload", "no"),
           ("files_sharing", "outgoing_server2server_share_enabled", "no"),
           ("files_sharing", "incoming_server2server_share_enabled", "no"),
           ("files_sharing", "lookupServerEnabled", "no"), ("files_sharing", "lookupServerUploadEnabled", "no"),
           ("user_oidc", "allow_multiple_user_backends", "0")]       # the login page goes straight to Kanidm

PG_HBA = "# chp-site documents enable: Unix socket only, peer authentication (no database password)\n" \
         "local all postgres peer\nlocal nextcloud apache peer\n"


def _p(root, rel):
    return Path(root) / rel.lstrip("/")


def _put(path, text, mode, chown=None):
    """Write only when the content or mode differs. Returns True when written."""
    try:
        if path.exists() and path.read_text() == text and (path.stat().st_mode & 0o7777) == mode:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".chp-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        if chown:
            chown(tmp)
        os.replace(tmp, path)
    except OSError as e:
        raise SiteError(f"could not write {path} ({e.strerror or e}); fix it, then re-run chp-site documents enable") \
            from None
    return True


def _kv(path):
    if not path.exists():
        return {}
    return dict(ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln and not ln.startswith("#"))


def conf_text(fqdn, server_ip, days, ids, enabled="yes"):
    """/etc/chp/documents.conf (0644, no secrets): read by the checks (77-79, Plan 2 Task 6), the units and Plan 3.
    ENABLED=yes is written by the LAST step of enable (it means every step succeeded once)."""
    lines = ["# written by chp-site documents enable; no secrets here", f"ENABLED={enabled}", f"FQDN={fqdn}",
             f"SERVER_IP={server_ip}", f"DOCUMENTS_BACKUP_DAYS={days}"]
    for n in CONTROLLED + OPEN:
        if n in ids:
            lines.append(f"{n.upper()}_FOLDER_ID={ids[n]}")
    return "\n".join(lines) + "\n"


def occ_run(argv, env=None):
    """The real occ: as the apache user, stdin closed. A secret travels only in `env` (whitelisted for runuser),
    never in argv. Returns (rc, stdout, stderr)."""
    pre = ["runuser", "-u", "apache"] + ([f"--whitelist-environment={','.join(sorted(env))}"] if env else []) + ["--"]
    cmd = pre + ["/usr/bin/php", "-d", "apc.enable_cli=1", "-d", "memory_limit=512M", "/usr/lib/nextcloud/occ", *argv]
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600,
                           env={**os.environ, **(env or {})})
    except subprocess.TimeoutExpired:
        raise SiteError(f"occ {argv[0]} timed out") from None
    return r.returncode, r.stdout, r.stderr


class _Occ:
    def __init__(self, occ):
        self._occ = occ

    def __call__(self, *argv, env=None, check=True):
        rc, out, err = self._occ(list(argv), env=env) if env else self._occ(list(argv))
        if check and rc != 0:
            why = (err or out or f"exit {rc}").strip().splitlines()
            raise SiteError(f"occ {argv[0]} failed: {(why[-1] if why else f'exit {rc}')[:200]}; fix the cause, then "
                            "re-run chp-site documents enable (it is safe to repeat)")
        return rc, out

    def json(self, *argv):
        _, out = self(*argv)
        try:
            return json.loads(out)
        except ValueError:
            raise SiteError(f"occ {argv[0]} did not return JSON: {out.strip()[:120]!r}") from None


def _refuse(host, site, hosts, root, data_is_mount):
    me = next((h for h in hosts if h.hostname == host), None)
    if me is None:
        raise SiteError(f"{host} is not in the hosts table")
    if me.role != "server":
        raise SiteError(f"documents enable runs on the CHP server only ({host} is a {me.role})")
    if site.get("DOCUMENTS") != "yes":
        raise SiteError("DOCUMENTS is not yes in site.conf: set DOCUMENTS=yes on the site stick, apply it, then re-run")
    if site.get("SECURITY_ADDONS") != "yes":
        raise SiteError("DOCUMENTS=yes needs SECURITY_ADDONS=yes (the document server's audit trail goes to Wazuh)")
    if _kv(_p(root, "etc/chp/security.conf")).get("ROLE") != "server":
        raise SiteError("the security add-on is not enabled on this server: run chp-site security enable first")
    if not data_is_mount:
        raise SiteError("DOCUMENTS=yes needs /data as its own volume (a server installed on a disk of 900 GB or more); "
                        "this server has no /data mount, so the document server is refused here")
    return me


def enable(host, site, hosts, *, run, occ, kanidm, root=Path("/"), record=None, stick=None,
           pending=Path("/root/chp-escrow-pending"), data_is_mount=None, chown=None, now=None, secret=None):
    """Returns the list of steps done. `stick`: the site stick (the break-glass secret is escrowed there at once);
    None leaves it in the pending folder for export-client (monitor 40 warns until then)."""
    from . import audit
    data_is_mount = os.path.ismount("/data") if data_is_mount is None else data_is_mount
    me = _refuse(host, site, hosts, root, data_is_mount)
    _mta_check(run)
    record = record or audit.record
    try:
        return _enable(me, site, hosts, run=run, occ=_Occ(occ), k=kanidm, root=Path(root), record=record, stick=stick,
                       pending=Path(pending), chown=chown, now=now or (lambda: time.strftime("%Y%m%dT%H%M%SZ",
                                                                                            time.gmtime())),
                       secret=secret)
    except subprocess.CalledProcessError as e:
        cmd = " ".join(e.cmd) if isinstance(e.cmd, (list, tuple)) else str(e.cmd)
        raise SiteError(f"{cmd} failed (exit {e.returncode}); see its log, fix the cause, then re-run "
                        "chp-site documents enable (it is safe to repeat)") from None


def _owner(chown, user, group):
    return chown or (lambda p: shutil.chown(p, user, group))


def _ok(run, argv):
    return run(argv, capture_output=True, text=True).returncode == 0


def _out(run, argv):
    return run(argv, capture_output=True, text=True).stdout or ""


def _restart_marks(root):
    p = _p(root, MARK)
    try:
        return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()] if p.exists() else []
    except OSError as e:
        raise SiteError(f"could not read {p} ({e.strerror or e})") from None


def _mark(root, units):
    """Record units that need a restart BEFORE the change that needs it: a run that fails between the change and the
    restart leaves the marker, and the next run restarts them although the file is unchanged by then."""
    have = _restart_marks(root)
    new = have + [u for u in units if u not in have]
    if new != have:
        _put(_p(root, MARK), "".join(u + "\n" for u in new), 0o600)


def _unmark(root, units):
    have = _restart_marks(root)
    left = [u for u in have if u not in units]
    if left != have:
        if left:
            _put(_p(root, MARK), "".join(u + "\n" for u in left), 0o600)
        else:
            try:
                _p(root, MARK).unlink()
            except OSError as e:
                raise SiteError(f"could not clear {_p(root, MARK)} ({e.strerror or e})") from None


def _differs(path, text, mode):
    try:
        return not (path.exists() and path.read_text() == text and (path.stat().st_mode & 0o7777) == mode)
    except OSError as e:
        raise SiteError(f"could not read {path} ({e.strerror or e})") from None


def _size_sha(path):
    """(size, sha256) of a file, None when it is absent."""
    import hashlib
    try:
        if not path.exists():
            return None
        b = path.read_bytes()
        return str(len(b)), hashlib.sha256(b).hexdigest()
    except OSError as e:
        raise SiteError(f"could not read {path} ({e.strerror or e})") from None


def _trust_entry(trust_file, target):
    """The (size, sha256) fapolicyd's trust file records for `target`; None when absent or unreadable as such
    (treated as stale)."""
    try:
        text = trust_file.read_text() if trust_file.exists() else ""
    except OSError as e:
        raise SiteError(f"could not read {trust_file} ({e.strerror or e})") from None
    for ln in text.splitlines():
        f = ln.split()
        if len(f) == 3 and f[0] == target and f[1].isdigit() and re.fullmatch(r"[0-9a-f]{64}", f[2]):
            return f[1], f[2]
    return None


def _put_r(root, path, text, mode, units, chown=None):
    """_put, with `units` marked for a restart first when the file is about to change."""
    if _differs(path, text, mode):
        _mark(root, units)
    return _put(path, text, mode, chown)


def _restart(run, root, units, extra=()):
    """Restart the units that are marked (or in `extra`), then clear their marks. A failed restart keeps them marked."""
    marks = _restart_marks(root)
    todo = [u for u in units if u in marks or u in extra]
    if todo:
        run(["systemctl", "restart", *todo], check=True)
        _unmark(root, todo)
    return todo


def _mta_check(run):
    """No local mail server at all (a unix-socket relay is a path the egress uid match cannot see). Run before any
    change: rpm -q needs nothing installed."""
    mta = [m for m in MTAS if _ok(run, ["rpm", "-q", m])]
    if mta:
        raise SiteError(f"a mail server is installed ({', '.join(mta)}): NextCloud's mail is off, but the apache user "
                        "could relay through a local MTA's socket, which the egress table cannot see. Remove it "
                        f"(dnf remove {' '.join(mta)}), then re-run chp-site documents enable")


def _write_zone(run, zp, text, d, chown):
    """The new zone is checked with named-checkzone as a temp file BEFORE it replaces the live one."""
    tmp = zp.with_name(zp.name + ".chp-new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o640)
    _owner(chown, "root", "named")(tmp)
    r = run(["named-checkzone", d, str(tmp)], capture_output=True, text=True)
    if r.returncode != 0:
        tmp.unlink()
        raise SiteError(f"the new site zone with the files record failed named-checkzone; the live zone is unchanged: "
                        + (r.stdout or r.stderr or "").strip()[:200])
    os.replace(tmp, zp)


def _perm_has_share(v):
    """groupfolders reports a group's permissions as a bitmask (share = 16), a dict holding it, or (fakes) words."""
    if isinstance(v, dict):
        v = v.get("permissions", 0)
    if isinstance(v, (list, tuple)):
        return "share" in v
    try:
        return bool(int(v) & 16)
    except (TypeError, ValueError):
        return True                                    # unreadable = assume the worst


def _folder_groups(occ):
    out = occ.json("groupfolders:list", "--output=json")
    items = out if isinstance(out, list) else list(out.values()) if isinstance(out, dict) else []
    return {str(f.get("id")): (f.get("groups") or {}) for f in items if isinstance(f, dict)}


def _exact_controlled(occ, ids):
    """CUI, FCI, Archive must be mapped to cui-users WITHOUT share and to nothing else (read back, never assumed).
    A stray group is removed; what cannot be removed or still has share is refused, naming it."""
    for _ in range(2):
        cur = _folder_groups(occ)
        stray = [(n, g) for n in CONTROLLED for g in cur.get(str(ids[n]), {}) if g != "cui-users"]
        if not stray:
            break
        for n, g in stray:
            occ("groupfolders:group", ids[n], g, "--delete")
    cur = _folder_groups(occ)
    for n in CONTROLLED:
        gs = cur.get(str(ids[n]), {})
        other = sorted(g for g in gs if g != "cui-users")
        if other:
            raise SiteError(f"team folder {n} is still mapped to {', '.join(other)} after removal; remove it "
                            f"(occ groupfolders:group {ids[n]} <group> --delete), then re-run")
        if "cui-users" not in gs:
            raise SiteError(f"team folder {n} is not mapped to cui-users after groupfolders:group")
        if _perm_has_share(gs["cui-users"]):
            raise SiteError(f"team folder {n} still gives cui-users the share permission; share must be off")


def _enable(me, site, hosts, *, run, occ, k, root, record, stick, pending, chown, now, secret):
    host = me.hostname
    fqdn, d = dr.fqdn(site), site["DOMAIN"]
    sip, cidr = server_of(hosts).ip, str(site["SUBNET"])
    origin = f"https://{fqdn}:{PORT}"
    done = []

    def step(name, text, **fields):
        done.append(text)
        record("documents-enable", {"host": host, "step": name, **fields}, after=True)

    record("documents-enable", {"host": host, "step": "start", "fqdn": fqdn})   # before any change; refuses if it fails

    cfg = _p(root, "etc/nextcloud/config.php")
    # 1. packages (the signed chp repo); a transaction this run means fapolicyd restarts at the end (never inside one)
    run(["dnf", "-y", "--enablerepo=chp", "module", "enable", "php:8.3", "postgresql:16"], check=True,
        capture_output=True, text=True)
    if not all(_ok(run, ["rpm", "-q", p]) for p in PACKAGES):
        _mark(root, ["fapolicyd"])
        run(["dnf", "-y", "--enablerepo=chp", "install", *PACKAGES], check=True)
    pgv = _out(run, ["rpm", "-q", "--qf", "%{VERSION}", "postgresql-server"]).strip()
    if pgv.split(".")[0] != "16":
        raise SiteError(f"postgresql-server is {pgv or 'not installed'}, not 16: the document server needs the "
                        "postgresql:16 stream (dnf module reset postgresql; dnf module enable postgresql:16)")
    step("packages", f"packages: nextcloud-chp, chp-documents (PHP 8.3, PostgreSQL {pgv}, httpd from Rocky)")
    step("mail", "mail: no mail server installed (postfix, sendmail, exim, opensmtpd absent); NextCloud mail off",
         mta="none")

    # 2. names without DNS for apache: /etc/hosts; the files record in the site zone for the LAN
    _put(_p(root, "etc/hosts"), dr.hosts_file(site, hosts), 0o644)
    step("hosts", f"/etc/hosts: the site names -> {sip} (apache has no DNS)")
    zp = _p(root, f"var/named/{d}.zone")
    if not zp.exists():
        raise SiteError(f"the site zone /var/named/{d}.zone is missing on this server")
    ztext = zp.read_text()
    if not re.search(rf"^files\s+IN\s+A\s+{re.escape(sip)}\s*$", ztext, re.M):
        from .render import zone
        m = re.search(r"\(\s*(\d+)", ztext)
        serial = max(int(m.group(1)) + 1 if m else 0, int(time.strftime("%Y%m%d")) * 100 + 1)
        _write_zone(run, zp, zone(site, hosts, serial), d, chown)
        run(["rndc", "reload", d], check=True, capture_output=True, text=True)
    step("dns", f"DNS: {fqdn} IN A {sip} in the site zone")

    # 3. site-rendered web and egress files (chp-documents ships them failing closed). ENABLED stays as it was
    # (no on a first run) until the very last step.
    _put_r(root, _p(root, LAN_INC), f"Require ip {cidr}\n", 0o644, ["httpd"])
    _put_r(root, _p(root, EGRESS_ADDR), f"define CHP_NC_SERVER_IP = {sip}\n", 0o644,
           ["chp-nextcloud-egress.service", "php-fpm", "httpd"])     # a re-IP must not leave the old address allowed
    cp = _p(root, CONF)
    old = _kv(cp)
    ids = {n: old[f"{n.upper()}_FOLDER_ID"] for n in CONTROLLED + OPEN if f"{n.upper()}_FOLDER_ID" in old}
    enabled_now = old.get("ENABLED", "no")
    days = site.get("DOCUMENTS_BACKUP_DAYS", 14)
    _put(cp, conf_text(fqdn, sip, days, ids, enabled_now), 0o644)
    step("render", f"rendered: LAN-only httpd ({cidr}), egress address {sip}, /etc/chp/documents.conf")
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", "--now", "chp-nextcloud-egress.service"], check=True)
    _restart(run, root, ["chp-nextcloud-egress.service"])
    step("egress", "egress table inet chp_nextcloud_egress loaded (apache: this server only, no DNS)")

    # 4. Wazuh from day one: the audit log and the rules before NextCloud writes its first line or serves anyone
    _audit_log(root, chown)
    _wazuh(root, run, chown)
    step("wazuh", "Wazuh: NextCloud audit log read; rules 100600-100630 (share/contain/app-off/tag/egress at 12)")

    # 5. database: PostgreSQL 16, Unix socket, peer authentication
    pgd = _p(root, PGDATA)
    if not (pgd / "PG_VERSION").exists():
        run(["postgresql-setup", "--initdb"], check=True, capture_output=True, text=True)
    pc = pgd / "postgresql.conf"
    text = pc.read_text() if pc.exists() else ""
    new = re.sub(r"^#?\s*listen_addresses\s*=.*$", "listen_addresses = ''", text, flags=re.M)
    if "listen_addresses = ''" not in new:
        new += ("" if new.endswith("\n") or not new else "\n") + "listen_addresses = ''\n"
    _put_r(root, pc, new, 0o600, ["postgresql"], _owner(chown, "postgres", "postgres"))
    _put_r(root, pgd / "pg_hba.conf", PG_HBA, 0o600, ["postgresql"], _owner(chown, "postgres", "postgres"))
    run(["systemctl", "enable", "--now", "postgresql"], check=True)
    _restart(run, root, ["postgresql"])
    psql = ["runuser", "-u", "postgres", "--", "psql", "-qtA", "-c"]
    if _out(run, psql + ["SELECT 1 FROM pg_roles WHERE rolname='apache'"]).strip() != "1":
        run(psql + ["CREATE ROLE apache LOGIN"], check=True, capture_output=True, text=True)
    if _out(run, psql + ["SELECT 1 FROM pg_database WHERE datname='nextcloud'"]).strip() != "1":
        run(psql + ["CREATE DATABASE nextcloud OWNER apache TEMPLATE template0 ENCODING 'UTF8'"], check=True,
            capture_output=True, text=True)
    step("database", f"database: PostgreSQL {pgv}, socket only, peer authentication, database nextcloud (owner apache)")

    # 6. NextCloud installed offline (no admin on the command line), data on /data
    if not _p(root, f"{DATA}/data").is_dir():                # labelled once; NextCloud's files inherit the label
        run(["install", "-d", "-m", "0750", "-o", "apache", "-g", "apache", DATA, f"{DATA}/data"], check=True)
        run(["restorecon", "-R", DATA], check=True)
    st = occ.json("status", "--output=json")
    if not st.get("installed"):
        occ("maintenance:install", "--database", "pgsql", "--database-name", "nextcloud", "--database-host",
            "/run/postgresql", "--database-user", "apache", "--database-pass", "", "--disable-admin-user",
            "--data-dir", f"{DATA}/data")
    # fapolicyd: config.php is PHP NextCloud itself writes -> a path trust entry (spike, trust step)
    tf = _p(root, "etc/fapolicyd/trust.d/nextcloud")
    if not (tf.exists() and CONFIG_PHP in tf.read_text()):
        _mark(root, ["fapolicyd"])
        run(["fapolicyd-cli", "--file", "add", "/etc/nextcloud/config.php", "--trust-file", "nextcloud"], check=True)
        run(["fapolicyd-cli", "--update"], check=True)
    step("install", f"NextCloud installed offline (data {DATA}/data)")

    # 7. settings: offline, hardening, logs; bcrypt (FIPS breaks PHP Argon2id) before any local account
    occ("config:system:set", "hashing_default_password", "--type=boolean", "--value=true")
    for keys, value, typ in _system(fqdn):
        occ("config:system:set", *keys, *([f"--type={typ}"] if typ else []), f"--value={value}")
    occ("background:cron")
    for app, key, value in SHARING:
        occ("config:app:set", app, key, f"--value={value}")
    step("settings", "settings: no internet connection, app store and update checker off, mail off, "
                     f"trusted domain {fqdn}, {origin}, sharing locked down")

    # 8. apps: exactly what the design needs on; editors and outbound features off
    enabled = set(occ.json("app:list", "--output=json").get("enabled", {}))
    for a in APPS_ON:
        if a not in enabled:
            occ("app:enable", a)
    for a in APPS_OFF:
        if a in enabled:
            occ("app:disable", a)
    enabled = set(occ.json("app:list", "--output=json").get("enabled", {}))
    if set(APPS_ON) - enabled or set(APPS_OFF) & enabled:
        raise SiteError(f"apps not as required: missing {sorted(set(APPS_ON) - enabled)}, still on "
                        f"{sorted(set(APPS_OFF) & enabled)}")
    step("apps", f"apps on: {', '.join(APPS_ON)}; editors and outbound apps off")

    # 9. break-glass admin (bcrypt; /login?direct=1); its secret escrowed, never printed or logged
    rc, _ = occ("user:info", ADMIN, check=False)
    pend = pending / "documents" / f"{host}-nextcloud-admin.secret"
    if rc != 0:
        pw = _pending_secret(pend, secret)
        occ("user:add", "--password-from-env", "--display-name", "Break-glass admin", "--group", "admin", ADMIN,
            env={"OC_PASS": pw})
        del pw
        step("breakglass", f"break-glass NextCloud admin {ADMIN} made (bcrypt); secret to the escrow")
    else:
        step("breakglass", f"break-glass NextCloud admin {ADMIN} present")

    # 10. Kanidm: groups and the OIDC client (ES256, PKCE S256, chp_groups claim)
    for g in ("cui-users", "doc-reviewers"):
        if k.group(g) is None:
            k.create_group(g)
    ent = k.oauth2(CLIENT)
    if ent is None:
        k.oauth2_create(CLIENT, "NextCloud", origin)
        ent = k.oauth2(CLIENT) or {}
    _check_client(ent)
    k.oauth2_add_redirect(CLIENT, f"{origin}/index.php/apps/user_oidc/code")
    k.oauth2_scope_map(CLIENT, "chp_users", ("openid", "profile", "email", "groups"))
    k.oauth2_prefer_short_username(CLIENT)
    for g, v in (("cui-users", "cui-users"), ("doc-reviewers", "doc-reviewers"), ("chp_users", "chp-users")):
        k.oauth2_claim_map(CLIENT, "chp_groups", g, v)
    k.oauth2_claim_join(CLIENT, "chp_groups", "array")
    sp = _p(root, OIDC_SECRET)
    if not (sp.exists() and sp.read_text().strip()):
        _put(sp, k.oauth2_basic_secret(CLIENT) + "\n", 0o640, _owner(chown, "root", "apache"))
        run(["restorecon", OIDC_SECRET], check=True)
    step("kanidm", "Kanidm: groups cui-users, doc-reviewers; OAuth2 client nextcloud (ES256, PKCE), chp_groups claim")

    # 11. NextCloud -> Kanidm: SELinux relay (the egress table limits where), the site CA, the provider
    if "--> on" not in _out(run, ["getsebool", "httpd_can_network_relay"]):
        run(["setsebool", "-P", "httpd_can_network_relay", "on"], check=True)
    if "chp-root.crt" not in occ("security:certificates")[1]:
        occ("security:certificates:import", SITE_ROOT_CA)
    # an upsert (spike folders.sh): applied every run so whitelist, mappings and discovery cannot drift
    occ("user_oidc:provider", "kanidm", f"--clientid={CLIENT}", f"--clientsecret-file={OIDC_SECRET}",
        f"--discoveryuri=https://idm.{d}/oauth2/openid/{CLIENT}/.well-known/openid-configuration",
        "--scope=openid profile email groups", "--unique-uid=0", "--mapping-uid=preferred_username",
        "--mapping-display-name=name", "--mapping-email=email", "--mapping-groups=chp_groups",
        "--group-provisioning=1", "--group-whitelist-regex=^(cui-users|doc-reviewers|chp-users)$",
        "--check-bearer=0", "--send-id-token-hint=1")
    step("oidc", "sign-in: user_oidc provider kanidm; the login page goes straight to Kanidm")

    # 12. groups, team folders, ACLs
    have = set(occ.json("group:list", "--output=json"))
    for g in GROUPS_NC:
        if g not in have:
            occ("group:add", g)
    ids = _folders(occ)
    for n in CONTROLLED + OPEN:
        if n not in ids:
            _, out = occ("groupfolders:create", n)
            m = re.search(r"\d+", out)
            if not m:
                raise SiteError(f"occ groupfolders:create {n} printed no folder id")
            ids[n] = m.group(0)
        if n in CONTROLLED:
            occ("groupfolders:group", ids[n], "cui-users", "read", "write", "delete")       # NO share
        else:
            occ("groupfolders:group", ids[n], "chp-users", "read", "write", "delete", "share")
        occ("groupfolders:permissions", ids[n], "--enable")
        if n in CONTROLLED:                                                               # owner decision 7
            occ("groupfolders:permissions", ids[n], "--group", "doc-reviewers", "--", "/", *REVIEWER_ACL)
    _exact_controlled(occ, ids)                       # read back: only cui-users, no share, on CUI/FCI/Archive
    step("folders", "team folders: " + ", ".join(f"{n}={ids[n]}" for n in CONTROLLED + OPEN)
         + "; read back: CUI/FCI/Archive mapped to cui-users only, share off; reviewers read-only there")

    # 13. tags by folder + containment (owner decision 3)
    tags = _tags(occ)
    for t in ("CUI", "FCI"):
        if t not in tags:
            occ("tag:add", t, "restricted")
    tags = _tags(occ)
    if not {"CUI", "FCI"} <= set(tags):
        raise SiteError("the CUI and FCI system tags are not there after tag:add")
    rules = {str(ids[n]): str(tags[t]) for n, t in FOLDER_TAG.items()}
    contain = [int(ids[n]) for n in CONTROLLED]
    allow = [[int(ids["CUI"]), int(ids["Archive"])], [int(ids["Archive"]), int(ids["CUI"])]]
    for key, val in (("rules", rules), ("contain", contain), ("contain_allow", allow)):
        occ("config:app:set", "chp_foldertag", key, f"--value={json.dumps(val, separators=(',', ':'))}")
    _put(cp, conf_text(fqdn, sip, days, ids, enabled_now), 0o644)
    step("tags", "tags: CUI folder and Archive -> CUI, FCI -> FCI; copy/move out refused except CUI <-> Archive")

    # 14. web: LAN-only firewall, certificate, services
    rich = f'rule family="ipv4" source address="{cidr}" port port="{PORT}" protocol="tcp" accept'
    if rich not in _out(run, ["firewall-cmd", "--permanent", "--list-rich-rules"]).splitlines():
        run(["firewall-cmd", "-q", "--permanent", "--add-rich-rule", rich], check=True)
        run(["firewall-cmd", "-q", "--reload"], check=True)
    if not _p(root, CERT).exists():
        _mark(root, ["httpd"])
        run(["/usr/libexec/chp/cert-renew-nextcloud", "--issue"], check=True)
    step("cert", f"certificate for {fqdn} from the site CA (renewed by chp-nextcloud-cert-renew.timer)")
    run(["systemctl", "enable", "--now", *UNITS], check=True)
    _restart(run, root, ["php-fpm", "httpd"])
    step("services", f"started: {', '.join(UNITS)} (HTTPS {PORT}, LAN {cidr} only)")

    # 15a. config.php's trust entry follows its content (spike §Under the CUI profile fix 2). Stateless: the entry
    # fapolicyd holds (trust.d/nextcloud: "<path> <size> <sha256>") is compared with the file itself on every run,
    # so a failed update in an earlier run, or NextCloud rewriting config.php between runs, is caught and fixed.
    if _trust_entry(tf, CONFIG_PHP) != _size_sha(cfg):
        _mark(root, ["fapolicyd"])
        run(["fapolicyd-cli", "--file", "update", CONFIG_PHP, "--trust-file", "nextcloud"], check=True)
        run(["fapolicyd-cli", "--update"], check=True)
        step("trust", f"fapolicyd trust entry for {CONFIG_PHP} refreshed (it did not match the file)")

    # 15. fapolicyd: only when needed (packages installed or trust entry added this run or by a failed run, or
    # chp-base's filesystem-mark change pending), AFTER every transaction; never in an rpm scriptlet
    fsmark = _p(root, FSMARK_PENDING)
    if _restart(run, root, ["fapolicyd"], extra=["fapolicyd"] if fsmark.exists() else []):
        fsmark.unlink(missing_ok=True)
        denied = next((ln.strip() for ln in _out(run, ["fapolicyd-cli", "--check-status"]).splitlines()
                       if ln.strip().startswith("Denied")), "Denied accesses: unknown")
        step("fapolicyd", f"fapolicyd restarted (rule 65 loaded); {denied}")
    else:
        step("fapolicyd", "fapolicyd: no restart needed")

    # 16. escrow, AIDE, and last: ENABLED=yes (every step above succeeded)
    if pend.exists():
        if stick is not None:
            from .escrow import move_documents_secrets
            move_documents_secrets(pending / "documents", stick, now())
            step("escrow", "break-glass secret written to the site stick (escrow/), read back, shredded here")
        else:
            step("escrow", "break-glass secret is in the pending folder: plug in the site stick and run "
                           "chp-site export-client")
    _put(cp, conf_text(fqdn, sip, days, ids, "yes"), 0o644)
    step("enabled", "documents.conf ENABLED=yes")
    step("aide", "AIDE: httpd, /etc/hosts and new units changed: refresh the baseline now with "
                 "chp-site aide-accept --approver \"<ISSO>\" --reason \"documents enable\"", aide_refresh="needed")
    return done


def _pending_secret(path, secret=None):
    """The break-glass password: reuse a pending one (a re-run after a failure), else a new random one, written 0600
    BEFORE it is used, so it is never lost."""
    import secrets as _s
    if path.exists():
        v = _kv(path).get("NEXTCLOUD_ADMIN_PASSWORD")
        if v:
            return v
    pw = secret or _s.token_urlsafe(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"# NextCloud break-glass admin (sign in at /login?direct=1)\nNEXTCLOUD_ADMIN_USER={ADMIN}\n"
                    f"NEXTCLOUD_ADMIN_PASSWORD={pw}\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:                              # nothing was made yet: the account needs this file first
        raise SiteError(f"could not write the break-glass secret file {path} ({e.strerror or e}); no account was "
                        "made; fix it, then re-run chp-site documents enable") from None
    return pw


def _check_client(ent):
    """ES256 and PKCE are Kanidm's defaults; a client switched to legacy crypto (RS256) or without PKCE is refused."""
    if (ent.get("oauth2_jwt_legacy_crypto_enable") or ["false"])[0] == "true":
        raise SiteError("the Kanidm OAuth2 client nextcloud has legacy crypto (RS256) on; turn it off "
                        "(kanidm system oauth2 disable-legacy-crypto nextcloud), then re-run")
    if (ent.get("oauth2_allow_insecure_client_disable_pkce") or ["false"])[0] == "true":
        raise SiteError("the Kanidm OAuth2 client nextcloud has PKCE turned off; turn it on "
                        "(kanidm system oauth2 enable-pkce nextcloud), then re-run")


def _folders(occ):
    out = occ.json("groupfolders:list", "--output=json")
    items = out if isinstance(out, list) else list(out.values()) if isinstance(out, dict) else []
    ids = {}
    for f in items:
        name = f.get("mount_point", f.get("mountPoint"))
        if name in CONTROLLED + OPEN:
            ids[name] = str(f.get("id"))
    return ids


def _tags(occ):
    out = occ.json("tag:list", "--output=json")
    if isinstance(out, dict):
        return {v.get("name"): str(i) for i, v in out.items() if isinstance(v, dict)}
    return {v.get("name"): str(v.get("id")) for v in out if isinstance(v, dict)}


def _audit_log(root, chown):
    """The audit log exists before Wazuh reads it (it reads a file that appears later from its end)."""
    p = _p(root, w.NC_AUDIT)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o640)
        os.close(fd)
        _owner(chown, "apache", "apache")(p)


def _wazuh(root, run, chown):
    grp = _owner(chown, "root", "wazuh")
    conf = _p(root, "var/ossec/etc/ossec.conf")
    rules = _p(root, f"var/ossec/etc/rules/{w.NC_RULES_FILE}")
    old_rules = rules.read_text() if rules.exists() else None
    old_conf = conf.read_text()
    new_conf = w.documents_manager(old_conf)
    changed = _differs(rules, w.NEXTCLOUD_RULES, 0o640) or _differs(conf, new_conf, 0o640)
    marked_before = "wazuh-manager" in _restart_marks(root)
    if changed:
        _mark(root, ["wazuh-manager"])
        _put(rules, w.NEXTCLOUD_RULES, 0o640, grp)
        _put(conf, new_conf, 0o640, grp)
    marked = "wazuh-manager" in _restart_marks(root)
    active = _out(run, ["systemctl", "is-active", "wazuh-manager"]).strip() == "active"
    if not (marked or not active):
        return
    r = run(["/var/ossec/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        why = (r.stderr or r.stdout or "").strip()[:200]
        if changed:
            if old_rules is None:
                try:
                    rules.unlink()
                except OSError as e:
                    raise SiteError(f"the new NextCloud rules failed wazuh-analysisd -t and could not be removed "
                                    f"({rules}: {e.strerror or e}); remove that file before restarting Wazuh") from None
            else:
                _put(rules, old_rules, 0o640, grp)
            _put(conf, old_conf, 0o640, grp)
            if not marked_before:                    # keep a mark an earlier failed restart left
                _unmark(root, ["wazuh-manager"])
            raise SiteError("the Wazuh rule check (wazuh-analysisd -t) failed on the new NextCloud rules; the old "
                            "rules are back and the manager was not restarted: " + why)
        raise SiteError("the Wazuh rule check (wazuh-analysisd -t) fails on the installed rules (nothing was changed "
                        "by this run); the manager was not restarted: " + why)
    _restart(run, root, ["wazuh-manager"], extra=["wazuh-manager"])


def status(root, run):
    """Lines for `chp-site documents status` (and the nightly check, §12)."""
    c = _kv(_p(root, CONF))
    if not c:
        return ["documents: not enabled on this host (chp-site documents enable, on the server)"]
    if c.get("ENABLED") != "yes":
        return ["documents: enable has not finished on this host (ENABLED is not yes): re-run chp-site documents "
                "enable"]
    rows = [f"documents: https://{c.get('FQDN')}:{PORT} (server {c.get('SERVER_IP')}); folders "
            + " ".join(f"{n}={c.get(n.upper() + '_FOLDER_ID', '?')}" for n in CONTROLLED + OPEN)]
    for u in STATUS_UNITS:
        st = _out(run, ["systemctl", "is-active", u]).strip() or "unknown"
        rows.append(f"{u.replace('.service', '')}: {st}")
    rows.append(md5_state(run))
    return rows


def md5_state(run):
    """§12: the same probe as chp_foldertag's FolderGuardListener (SELECT MD5('chp') on NextCloud's database, compared
    with md5('chp')), as the apache user over the socket (peer authentication)."""
    r = run(["runuser", "-u", "apache", "--", "psql", "-d", "nextcloud", "-qtA", "-c", "SELECT MD5('chp')"],
            capture_output=True, text=True)
    if r.returncode == 0 and (r.stdout or "").strip() == MD5_CHP:
        return "database MD5: available (folder moves, renames and deletes allowed)"
    return "DEGRADED: database MD5 unavailable (folder moves/renames/deletes refused)"
