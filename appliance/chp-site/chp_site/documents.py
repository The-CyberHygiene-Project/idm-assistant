# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""chp-site documents enable|status|check (ISO 0.7.0 design §2, §3, §5, §6, §12; Plan 2 Tasks 5-6): NextCloud as the site's local,
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


def _trust_lines(trust_file, target):
    """Every line of fapolicyd's trust file that is for `target`, as (size, sha256), or None for a line that names
    `target` but is malformed. Lines are "<path> <size> <sha256>", parsed from the right so a path may hold spaces;
    the path must equal `target` exactly (config.php.bak is not config.php)."""
    try:
        text = trust_file.read_text() if trust_file.exists() else ""
    except OSError as e:
        raise SiteError(f"could not read {trust_file} ({e.strerror or e})") from None
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        f = ln.rsplit(None, 2)
        if len(f) == 3 and re.fullmatch(r"0|[1-9][0-9]*", f[1]) and re.fullmatch(r"[0-9a-f]{64}", f[2]):
            if f[0] == target:
                out.append((f[1], f[2]))
        elif ln == target or (ln.startswith(target) and ln[len(target)].isspace()):
            out.append(None)                                  # names target, but not a valid entry
    return out


def _trust_entry(trust_file, target):
    """The (size, sha256) fapolicyd's trust file records for `target`; None (treated as stale) unless there is
    EXACTLY ONE valid entry for it (none, a malformed one, or duplicates all mean: refresh)."""
    m = _trust_lines(trust_file, target)
    return m[0] if len(m) == 1 else None


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
    if not _trust_lines(tf, CONFIG_PHP):                    # no entry at all (a stale one: step 15a)
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
        try:
            v = _kv(path).get("NEXTCLOUD_ADMIN_PASSWORD")
        except OSError as e:
            raise SiteError(f"could not read the pending break-glass secret file {path} ({e.strerror or e}); no "
                            "account was made; fix it, then re-run chp-site documents enable") from None
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
    try:
        old_rules = rules.read_text() if rules.exists() else None
    except OSError as e:
        raise SiteError(f"could not read {rules} ({e.strerror or e})") from None
    try:
        old_conf = conf.read_text()
    except OSError as e:
        raise SiteError(f"could not read {conf} ({e.strerror or e})") from None
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
            # Roll back each piece on its own: a failure on one never stops the others (ossec.conf is restored and
            # the restart mark handled even when the rules file cannot be put back).
            done_, notdone = [], []
            try:
                if old_rules is None:
                    try:
                        rules.unlink()
                    except FileNotFoundError:
                        pass
                    done_.append(f"the new rules file {rules} is removed")
                else:
                    _put(rules, old_rules, 0o640, grp)
                    done_.append(f"the previous {rules} is back")
            except OSError as e:
                notdone.append(f"the new rules file {rules} could not be removed ({e.strerror or e})")
            except SiteError as e:
                notdone.append(f"the previous {rules} could not be restored ({e})")
            try:
                _put(conf, old_conf, 0o640, grp)
                done_.append(f"the previous {conf} is back")
            except SiteError as e:
                notdone.append(f"{conf} could not be restored ({e})")
            if not marked_before:                    # keep a mark an earlier failed restart left
                try:
                    _unmark(root, ["wazuh-manager"])
                except SiteError as e:
                    notdone.append(f"the wazuh-manager restart mark could not be cleared ({e})")
            if notdone:
                raise SiteError("the Wazuh rule check (wazuh-analysisd -t) failed on the new NextCloud rules; "
                                + "; ".join(done_ + ["NOT rolled back: " + "; ".join(notdone)])
                                + "; the manager was not restarted; fix that by hand before restarting Wazuh: " + why)
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


# ---------- the nightly tag check and share-link canary (design §5, §6, §12; Plan 2 Task 6) ----------
# Runs from chp-site (chp-documents-check.timer), never from chp_foldertag: with the app off its own command is gone
# (spike §Tag by folder). It reads NextCloud's database with SQL (as apache over the socket, peer authentication) and
# trusts nothing the app or enable configured: folders, groups, tags, the app's policy and every file are read back.

CHECK_RESULT = "var/lib/chp/documents/check.json"     # chp-documents' state dir (0700); read by check 81 and Task 7
CANARY_USER = "chp-canary"                            # local NextCloud account, cui-users, DISABLED between runs
CANARY_TOKEN = "chp-canary"                           # name of the per-run app token (deleted at the end of each run)
CANARY_NAME = "CUI_chp-canary.txt"
CANARY_FILE = "CUI/" + CANARY_NAME
CANARY_RULES = "var/ossec/etc/rules/chp_nextcloud_rules_canary.xml"   # sorts after chp_nextcloud_rules.xml (parents)
CHECK_LOCK = "var/lib/chp/documents/check.lock"       # one check (or canary-off) at a time
CANARY_BODY = b"CHP share canary (no CUI content). The nightly check tries to share this file and expects a refusal.\n"
OCS_SHARES = "/ocs/v2.php/apps/files_sharing/api/v1/shares"
LIST_MAX = 50                                         # per kind (and folder) of finding; then one "more" alert
SHARE_BIT = 16

_DIR = "(SELECT id FROM oc_mimetypes WHERE mimetype = 'httpd/unix-directory')"
_LIVE = "substr(f.path, 1, 6) = 'files/'"             # live files only (not trash/, versions/, uploads/, appdata)


def _has_tag(tag):
    return ("EXISTS (SELECT 1 FROM oc_systemtag_object_mapping o WHERE o.objecttype = 'files' AND o.systemtagid = "
            f"{int(tag)} AND o.objectid = CAST(f.fileid AS VARCHAR(64)))")


Q_FOLDERS = "SELECT folder_id, mount_point, storage_id FROM oc_group_folders ORDER BY folder_id"
Q_GROUPS = "SELECT folder_id, group_id, permissions FROM oc_group_folders_groups ORDER BY folder_id, group_id"
Q_TAGS = "SELECT id, name, visibility, editable FROM oc_systemtag WHERE name IN ('CUI', 'FCI') ORDER BY id"
Q_APP = "SELECT configkey, configvalue FROM oc_appconfig WHERE appid = 'chp_foldertag'"


def _live_in(storage):
    """The filter the tag check and its positive control share: live files (not folders) in one storage."""
    return f"f.storage = {int(storage)} AND {_LIVE} AND f.mimetype NOT IN {_DIR}"


def _lim(limit):
    return f" ORDER BY f.fileid LIMIT {int(limit)}" if limit is not None else ""


def q_count(query):
    """The true total of a finding query built with limit=None."""
    return f"SELECT count(*) AS n FROM ({query}) x"


def q_untagged(storage, tag, limit=LIST_MAX + 1):
    """Every live file (not a folder) in one team folder's storage without the folder's tag."""
    return f"SELECT f.fileid, f.storage, f.path FROM oc_filecache f WHERE {_live_in(storage)} AND NOT {_has_tag(tag)}" \
        + _lim(limit)


def q_control(storage, tag):
    """Positive control: the SAME filter as q_untagged must find the canary file in the CUI storage, carrying the CUI
    tag. If it does not, the path/storage/tag assumptions of the whole check are wrong."""
    return (f"SELECT f.fileid FROM oc_filecache f WHERE {_live_in(storage)} AND {_has_tag(tag)} "
            f"AND f.path = 'files/{CANARY_NAME}'")


def q_named(cui, fci, limit=LIST_MAX + 1):
    """Every live CUI_/FCI_ file anywhere (any case) without the CUI/FCI tag its name asks for. Trash and old
    versions are not live files (not under files/) and are not checked."""
    pre = "upper(substr(f.name, 1, 4))"
    return (f"SELECT f.fileid, f.storage, f.path, s.id AS storage_name FROM oc_filecache f "
            f"JOIN oc_storages s ON s.numeric_id = f.storage WHERE {_LIVE} AND f.mimetype NOT IN {_DIR} "
            f"AND (({pre} = 'CUI_' AND NOT {_has_tag(cui)}) OR ({pre} = 'FCI_' AND NOT {_has_tag(fci)}))") + _lim(limit)


def q_outside(storages, cui, fci, limit=LIST_MAX + 1):
    """Every live file tagged CUI or FCI that is not in a controlled team folder (copied/moved out, or tagged by hand)."""
    st = ", ".join(str(int(s)) for s in storages) or "-1"
    return (f"SELECT f.fileid, f.storage, f.path, s.id AS storage_name FROM oc_filecache f "
            f"JOIN oc_storages s ON s.numeric_id = f.storage WHERE {_LIVE} AND f.storage NOT IN ({st}) "
            f"AND ({_has_tag(cui)} OR {_has_tag(fci)})") + _lim(limit)


def q_shares(storages, limit=LIST_MAX + 1):
    """Every share (any type) on anything in a controlled team folder: there must be none."""
    st = ", ".join(str(int(s)) for s in storages) or "-1"
    return (f"SELECT sh.id, sh.share_type, f.fileid, f.storage, f.path FROM oc_share sh "
            f"JOIN oc_filecache f ON f.fileid = sh.file_source WHERE f.storage IN ({st})") \
        + (f" ORDER BY sh.id LIMIT {int(limit)}" if limit is not None else "")


def sql_runner(run):
    """The real database: one query as the apache user over the socket (peer authentication, no password), the rows
    returned as JSON by PostgreSQL itself (json_agg), so names with any character in them arrive intact."""
    def q(query):
        wrapped = f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({query}) t"
        r = run(["runuser", "-u", "apache", "--", "psql", "-d", "nextcloud", "-qtAX", "-v", "ON_ERROR_STOP=1", "-c",
                 wrapped], capture_output=True, text=True)
        if r.returncode != 0:
            why = (r.stderr or r.stdout or f"exit {r.returncode}").strip().splitlines()
            raise SiteError(f"psql failed: {(why[-1] if why else '')[:200]}")
        try:
            rows = json.loads((r.stdout or "").strip() or "[]")
        except ValueError:
            raise SiteError("psql did not return JSON") from None
        if not isinstance(rows, list):
            raise SiteError("psql did not return a list of rows")
        return rows
    return q


def https_api(conf):
    """NextCloud's own HTTPS front door as a user sees it (the canary must cross the same checks a browser does):
    https://<FQDN>:8443 (FQDN -> SERVER_IP via /etc/hosts), verified against the site root CA. The app token is only
    ever in memory and in the Authorization header."""
    import base64
    import http.client
    import ssl
    import urllib.parse
    fqdn = conf.get("FQDN", "")

    def call(method, path, user, token, form=None, body=None):
        ctx = ssl.create_default_context(cafile=SITE_ROOT_CA)
        conn = http.client.HTTPSConnection(fqdn, PORT, context=ctx, timeout=60)
        h = {"Authorization": "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode(),
             "OCS-APIRequest": "true", "Accept": "application/json", "User-Agent": "CHP nightly share canary"}
        if form is not None:
            body = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if method == "PROPFIND":
            h["Depth"] = "0"
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return r.status, r.read(1 << 20)
        finally:
            conn.close()
    return call


def _clean(x, n=300):
    """Text from NextCloud (file, folder, user names) and errors: no control characters (review_report._cell), cut."""
    from .review_report import _cell
    s = _cell(x).strip()
    return s if len(s) <= n else s[:n - 3] + "..."


class _CanaryError(Exception):
    pass


def _o(occ, *argv, env=None, secret=False):
    """occ, or _CanaryError. `secret`: the output may hold a token, so it is never put into the error text."""
    rc, out, err = occ(list(argv), env=env) if env else occ(list(argv))
    if rc != 0:
        if secret:
            raise _CanaryError(f"occ {argv[0]} failed (exit {rc}; output not shown, it may hold a secret)")
        why = (err or out or f"exit {rc}").strip().splitlines()
        raise _CanaryError(f"occ {argv[0]} failed: {(why[-1] if why else '')[:160]}")
    return out or ""


def _jl(text):
    try:
        return json.loads(text)
    except ValueError:
        raise _CanaryError(f"occ did not return JSON: {text.strip()[:80]!r}") from None


def _canary_info(occ):
    """user:info for the canary: (rc, output) when it exists, None ONLY when NextCloud says the user is not there.
    Any other failure (occ broken, database down, maintenance mode) raises _CanaryError: never taken as 'absent'."""
    rc, out, err = occ(["user:info", CANARY_USER, "--output=json"])
    if rc == 0:
        return out or ""
    text = f"{out or ''} {err or ''}"
    if re.search(r"(?i)user (was )?not found|does not exist|no such user", text):
        return None
    why = (err or out or f"exit {rc}").strip().splitlines()
    raise _CanaryError(f"occ user:info {CANARY_USER} failed: {(why[-1] if why else '')[:160]}")


def _canary_account(occ):
    """The canary account: local, in cui-users, a random password nobody keeps (sign-in only by a per-run token).
    Returns (user:info as a dict, True when it was made just now)."""
    import secrets as _s
    out = _canary_info(occ)
    made = out is None
    if made:
        _o(occ, "user:add", "--password-from-env", "--display-name", "CHP share canary (nightly check)", "--group",
           "cui-users", CANARY_USER, env={"OC_PASS": _s.token_urlsafe(32)})
        _o(occ, "user:disable", CANARY_USER)
        out = _o(occ, "user:info", CANARY_USER, "--output=json")
    info = _jl(out)
    info = info if isinstance(info, dict) else {}
    if "cui-users" not in (info.get("groups") or []):
        _o(occ, "group:adduser", "cui-users", CANARY_USER)
    return info, made


def _tokens(occ):
    """Every app token of the canary account (it owns no token outside a run, whatever its name)."""
    toks = _jl(_o(occ, "user:auth-tokens:list", CANARY_USER, "--output=json"))
    items = toks if isinstance(toks, list) else list(toks.values()) if isinstance(toks, dict) else []
    return [t for t in items if isinstance(t, dict)]


def _drop_tokens(occ):
    for t in _tokens(occ):
        _o(occ, "user:auth-tokens:delete", CANARY_USER, str(t.get("id")))


def _is_on(v):
    return v is True or str(v).lower() in ("true", "1", "yes")


def canary_off(root, occ, lock=True):
    """`chp-site documents canary-off` (ExecStopPost of chp-documents-check.service, so it runs after a failure, a
    timeout or a kill too): delete every token of the canary account and disable it. Skipped while a check runs."""
    import fcntl
    fd = None
    if lock:
        fd = _lock(root)
        if fd is None:
            return ["OK canary-off: a check is running; it switches the canary off itself"]
    try:
        try:
            if _canary_info(occ) is None:
                return ["OK canary-off: no canary account"]
            _drop_tokens(occ)
            _o(occ, "user:disable", CANARY_USER)
        except _CanaryError as e:                     # the unit shows failed (journal); the next run alerts canary:leftover
            raise SiteError(f"canary-off: {e}; the canary account may still be enabled") from None
        return ["OK canary-off: canary account disabled, its app tokens deleted"]
    finally:
        if fd is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _lock(root):
    """A non-blocking exclusive lock in the state dir; None when another check holds it."""
    import fcntl
    p = _p(root, CHECK_LOCK)
    try:
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError as e:
        raise SiteError(f"could not open {p} ({e.strerror or e})") from None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _ocs(body):
    try:
        o = json.loads(body or b"{}").get("ocs", {})
        return o.get("meta", {}) or {}, o.get("data")
    except (ValueError, AttributeError):
        return {}, None


def _canary(occ, api, alert, ready=None):
    """Try a public link and an internal share (to the break-glass admin, not in cui-users) on the CUI canary file,
    as a cui-users member, through the OCS API. 403 = refused (OK). Anything created is ALERTED and deleted at once;
    whatever happens, every share on the canary file is swept and the token and account are switched off again.
    `ready()` runs once the canary file is there, before any share attempt (positive control, canary Wazuh rule)."""
    import secrets as _s
    import urllib.parse
    res = {"public": "not run", "internal": "not run"}
    made, gone, token = [], set(), None
    dav = f"/remote.php/dav/files/{CANARY_USER}/" + urllib.parse.quote(CANARY_FILE)

    def call(method, path, form=None, body=None):
        return api(method, path, CANARY_USER, token, form, body) if body is not None else \
            api(method, path, CANARY_USER, token, form)

    def delete(sid):
        try:
            st, _ = call("DELETE", f"{OCS_SHARES}/{sid}?format=json")
        except Exception:                                     # noqa: BLE001 - reported by the caller
            return False
        if st == 200:
            gone.add(sid)
        return st == 200

    def attempt(which, label, form):
        st, body = call("POST", f"{OCS_SHARES}?format=json", form)
        meta, data = _ocs(body)
        code = meta.get("statuscode")
        if st == 200 and code in (100, 200):
            sid = str(data.get("id", "")) if isinstance(data, dict) else ""
            ok = bool(re.fullmatch(r"\d+", sid)) and (made.append(sid) or delete(sid))
            alert(f"canary:{which}", f"share canary: a {label} on the CUI canary file was CREATED (share refusal is NOT "
                  "working on CUI); " + ("it was deleted at once" if ok else
                                         f"it could NOT be deleted (share id {sid or '?'}): delete it now"))
            return "CREATED, deleted" if ok else "CREATED, NOT deleted"
        if st == 403:
            return "refused"
        alert("canary:error", f"share canary ({label}) inconclusive: HTTP {st}, OCS {code}: "
                              f"{_clean(meta.get('message', ''), 120)} (the refusal was not proved)")
        return f"inconclusive (HTTP {st})"

    try:
        info, new = _canary_account(occ)
        toks = _tokens(occ)
        if not new and (_is_on(info.get("enabled")) or toks):  # between runs it is disabled with no token
            alert("canary:leftover", "share canary: the canary account was found "
                  + " and ".join((["ENABLED"] if _is_on(info.get("enabled")) else [])
                                 + ([f"with {len(toks)} app token(s)"] if toks else []))
                  + " before this run (a killed run, or someone used it): check the NextCloud audit log for "
                    f"{CANARY_USER}; cleaned up now")
        _drop_tokens(occ)
        _o(occ, "user:enable", CANARY_USER)
        lines = [x.strip() for x in _o(occ, "user:auth-tokens:add", "-n", "--name", CANARY_TOKEN,
                                       CANARY_USER, secret=True).splitlines() if x.strip()]
        token = lines[-1] if lines and re.fullmatch(r"[A-Za-z0-9_-]{16,}", lines[-1]) else None
        if token is None:
            raise _CanaryError("occ user:auth-tokens:add printed no token")
        st, _ = call("PROPFIND", dav)
        if st == 404:
            st, _ = call("PUT", dav, body=CANARY_BODY)
            if st not in (201, 204):
                raise _CanaryError(f"could not create the canary file {CANARY_FILE} (HTTP {st})")
        elif st != 207:
            raise _CanaryError(f"could not read the canary file {CANARY_FILE} (HTTP {st})")
        if ready is not None:
            ready()
        res["public"] = attempt("public", "public link", {"path": "/" + CANARY_FILE, "shareType": "3",
                                                          "permissions": "1", "password": "Canary-" + _s.token_urlsafe(18)})
        res["internal"] = attempt("internal", f"internal share to {ADMIN} (not in cui-users)",
                                  {"path": "/" + CANARY_FILE, "shareType": "0", "permissions": "1", "shareWith": ADMIN})
    except Exception as e:                                    # noqa: BLE001 - a nightly check reports, never crashes
        alert("canary:error", f"share canary could not run to the end: {_clean(e, 200)}")
    finally:
        if token is not None:                                  # sweep: any share on the canary file, however made
            try:
                st, body = call("GET", f"{OCS_SHARES}?format=json&path=" + urllib.parse.quote("/" + CANARY_FILE))
                _, data = _ocs(body)
                for s in (data if st == 200 and isinstance(data, list) else []):
                    sid = str(s.get("id", "")) if isinstance(s, dict) else ""
                    if re.fullmatch(r"\d+", sid) and sid not in made:
                        made.append(sid)
            except Exception as e:                            # noqa: BLE001
                alert("canary:cleanup", f"share canary: could not list shares on the canary file: {_clean(e, 160)}")
            for sid in made:
                if sid not in gone and not delete(sid):
                    alert("canary:cleanup", f"share canary: share {sid} on the CUI canary file could NOT be deleted: "
                                            "delete it now")
        for what, fn in (("token", lambda: _drop_tokens(occ)), ("account", lambda: _o(occ, "user:disable", CANARY_USER))):
            try:
                fn()
            except Exception as e:                            # noqa: BLE001
                alert("canary:cleanup", f"share canary: could not switch off the canary {what}: {_clean(e, 160)}")
    return res


def _json_or(v):
    try:
        return json.loads(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return ValueError


def _scalar(x):
    return str(x) if isinstance(x, (int, str)) and not isinstance(x, bool) else None


def _app_policy(app, ids, tagid, alert):
    """chp_foldertag's policy must be PRESENT and equal to what the site requires (a missing contain silently turns
    containment off; a missing rule leaves a folder untagged)."""
    if app.get("enabled") != "yes":
        alert("app:enabled", "chp_foldertag is not enabled (tagging and containment are OFF): "
                             "occ app:enable chp_foldertag, then find out who switched it off")
    have_ids = all(ids.get(n) for n in CONTROLLED)
    want_rules = {ids[n]: tagid[t] for n, t in FOLDER_TAG.items()} if have_ids and all(
        tagid.get(t) for t in FOLDER_TAG.values()) else None
    want_contain = sorted(ids[n] for n in CONTROLLED) if have_ids else None
    want_allow = sorted([(ids["CUI"], ids["Archive"]), (ids["Archive"], ids["CUI"])]) if have_ids else None
    fix = "; re-run chp-site documents enable"

    r = _json_or(app.get("rules"))
    if not r:
        alert("app:rules", "chp_foldertag rules are missing or empty (nothing is tagged)" + fix)
    else:
        got = {_scalar(k): _scalar(v) for k, v in r.items()} if isinstance(r, dict) else None
        if want_rules is not None and got != want_rules:
            alert("app:rules", f"chp_foldertag rules do not match the site policy (CUI and Archive -> CUI tag, FCI -> FCI "
                               f"tag): want {json.dumps(want_rules, sort_keys=True)}, have {_clean(app.get('rules'), 160)}"
                  + fix)
    c = _json_or(app.get("contain"))
    if not c:
        alert("app:contain", "chp_foldertag contain is missing or empty (copy/move OUT of CUI, FCI and Archive is NOT "
                             "refused)" + fix)
    else:
        got = sorted(map(str, (_scalar(x) for x in c))) if isinstance(c, list) else None
        if want_contain is not None and got != want_contain:
            alert("app:contain", f"chp_foldertag contain does not match the site policy (CUI, FCI, Archive): want "
                                 f"{want_contain}, have {_clean(app.get('contain'), 160)}" + fix)
    a = _json_or(app.get("contain_allow"))
    if not a:
        alert("app:contain_allow", "chp_foldertag contain_allow is missing or empty (CUI <-> Archive moves are refused)"
              + fix)
    else:
        ok = isinstance(a, list) and all(isinstance(p, list) and len(p) == 2 for p in a)
        got = sorted((_scalar(p[0]), _scalar(p[1])) for p in a) if ok else None
        if want_allow is not None and got != want_allow:
            alert("app:contain_allow", f"chp_foldertag contain_allow does not match the site policy (only CUI <-> "
                                       f"Archive): have {_clean(app.get('contain_allow'), 160)}" + fix)


def _policy(db, ids, alert):
    folders = {str(f.get("folder_id")): f for f in db["folders"]}
    groups = {}
    for g in db["groups"]:
        groups.setdefault(str(g.get("folder_id")), []).append(g)
    for n in CONTROLLED + OPEN:
        i = ids.get(n)
        if not i:
            alert(f"conf:{n}", f"/etc/chp/documents.conf has no valid {n} folder id; re-run chp-site documents enable")
            continue
        f = folders.get(i)
        if f is None:
            alert(f"folder:{i}", f"team folder {n} (id {i}) is missing from NextCloud; re-run chp-site documents enable")
        elif f.get("mount_point") != n:
            alert(f"folder:{i}", f"team folder id {i} must be named {n} but is named \"{_clean(f.get('mount_point'), 80)}\" "
                                 "(renamed in the web UI?): rename it back")
    known = {v for v in ids.values() if v}
    for i, f in folders.items():
        if i in known:
            continue
        names = sorted(str(g.get("group_id")) for g in groups.get(i, []))
        cui = "cui-users" in names
        alert(f"folder:{i}", f"team folder \"{_clean(f.get('mount_point'), 80)}\" (id {i}) is not one of the site's "
                             "folders" + ("; it gives cui-users access but is NOT tagged or contained (a renamed CUI, FCI "
                                          "or Archive folder?): move its files into the right folder, then delete it"
                                          if cui else f"; groups: {_clean(', '.join(names) or 'none', 80)}"))
    for n in CONTROLLED:
        i = ids.get(n)
        if not i or i not in folders:
            continue
        gs = groups.get(i, [])
        other = sorted(_clean(g.get("group_id") or "a circle", 40) for g in gs if g.get("group_id") != "cui-users")
        cu = [g for g in gs if g.get("group_id") == "cui-users"]
        bad = []
        if other:
            bad.append(f"also mapped to {', '.join(other)}")
        if not cu:
            bad.append("not mapped to cui-users")
        elif any(int(g.get("permissions") or 0) & SHARE_BIT for g in cu):
            bad.append("cui-users has the share permission")
        if bad:
            alert(f"groups:{i}", f"team folder {n} (id {i}): {'; '.join(bad)} (must be cui-users only, share off); "
                                 "re-run chp-site documents enable")
    tagid = {}
    for t in ("CUI", "FCI"):
        rows = [x for x in db["tags"] if x.get("name") == t]
        if not rows:
            alert(f"tag:{t}", f"the system tag {t} is missing; re-run chp-site documents enable")
            continue
        if len(rows) > 1:
            alert(f"tag:{t}:duplicate", f"there are {len(rows)} system tags named {t} (ids "
                                        f"{', '.join(str(x.get('id')) for x in rows)}): the check uses the lowest; "
                                        "merge them by hand and re-run chp-site documents enable")
        row = rows[0]
        tagid[t] = str(row.get("id"))
        if not (int(row.get("visibility") or 0) == 1 and int(row.get("editable") or 0) == 0):
            alert(f"tag:{t}", f"the system tag {t} is not restricted (users could add or remove it): "
                              f"occ tag:edit {tagid[t]} --access restricted")
    _app_policy({str(r.get("configkey")): r.get("configvalue") for r in db["app"]}, ids, tagid, alert)
    return folders, tagid


def _where(row, folders_by_storage):
    path = str(row.get("path") or "")
    rel = path[6:] if path.startswith("files/") else path
    st = row.get("storage")
    if st in folders_by_storage:
        return f"{folders_by_storage[st]}/{rel}"
    name = str(row.get("storage_name") or f"storage {st}")
    if name.startswith("home::"):
        return f"home of {name[6:]}: {rel}"
    return f"{name}: {rel}"


def _storages(folders, ids, alert):
    """The controlled folders' storages. A controlled folder without one is ALERTED (its files cannot be seen)."""
    out = {}
    for n in CONTROLLED:
        i = ids.get(n)
        if i not in folders:
            continue                                  # missing folder: alerted by _policy
        st = folders[i].get("storage_id")
        if isinstance(st, int) and not isinstance(st, bool) or (isinstance(st, str) and st.isdigit()):
            out[n] = int(st)
        else:
            alert(f"storage:{i}", f"team folder {n} (id {i}) has no storage id in oc_group_folders "
                                  f"({_clean(st, 20)}): the tag check cannot see its files (groupfolders not in "
                                  "separate-storage mode?)")
    return out


def _files(sql, folders, ids, tagid, storages, alert):
    by_storage = {}
    for f in folders.values():
        try:
            by_storage[int(f.get("storage_id"))] = str(f.get("mount_point"))
        except (TypeError, ValueError):
            pass
    counts = {}

    def report(kind, scope, build, text, key="fileid"):
        """The first LIST_MAX findings one alert each (key per file or share); the true total by count(*); beyond
        LIST_MAX one `<kind>[:<scope>]:more` alert."""
        rows = sql(build(LIST_MAX + 1))
        total = len(rows)
        if total > LIST_MAX:
            n = sql(q_count(build(None)))
            total = int((n[0] if n else {}).get("n") or total)
        for r in rows[:LIST_MAX]:
            alert(f"{kind}:{r.get(key)}", text(r))
        tag = f"{kind}:{scope}" if scope else kind
        if total > LIST_MAX:
            alert(f"{tag}:more", f"{total} findings in total ({tag}); only the first {LIST_MAX} are listed: run "
                                 "chp-site documents check again after fixing them")
        counts[tag] = total
        return rows

    untagged_ids = set()
    for n in CONTROLLED:
        st, t = storages.get(n), tagid.get(FOLDER_TAG[n])
        if st is None or t is None:
            continue
        rows = report("untagged", n, lambda lim, st=st, t=t: q_untagged(st, t, lim),
                      lambda r, n=n: f"file {_clean(_where(r, by_storage), 200)} (id {r.get('fileid')}) in team folder "
                                     f"{n} has no {FOLDER_TAG[n]} tag")
        untagged_ids.update(r.get("fileid") for r in rows)
    if tagid.get("CUI") and tagid.get("FCI"):
        cui, fci = tagid["CUI"], tagid["FCI"]
        report("name", None, lambda lim: q_named(cui, fci, lim),
               lambda r: f"file {_clean(_where(r, by_storage), 200)} (id {r.get('fileid')}) is named CUI_/FCI_ but has "
                         "no matching tag" + (" (also in its folder's list)" if r.get("fileid") in untagged_ids else ""))
        report("outside", None, lambda lim: q_outside(storages.values(), cui, fci, lim),
               lambda r: f"file {_clean(_where(r, by_storage), 200)} (id {r.get('fileid')}) is tagged CUI/FCI but is "
                         "outside CUI, FCI and Archive")
    report("share", None, lambda lim: q_shares(storages.values(), lim),
           lambda r: f"share {r.get('id')} (type {r.get('share_type')}) exists on "
                     f"{_clean(_where(r, by_storage), 200)} in a controlled team folder: delete it now", key="id")
    return counts


def _write_result(root, data):
    p = _p(root, CHECK_RESULT)
    try:
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(p.parent, 0o700)
        tmp = p.with_name(p.name + ".chp-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except OSError as e:
        raise SiteError(f"could not write {p} ({e.strerror or e}); check 81 will report the result as missing/stale") \
            from None


def _canary_rules(root, run, fid, alert, chown=None):
    """The Wazuh rule that lowers the nightly canary's refusal to level 3 is anchored to the canary FILE id (known only
    once the file exists), so the canary account sharing anything else still pages at 12. Written only when it
    changes; checked with wazuh-analysisd -t (rolled back on failure) before the manager restarts."""
    p = _p(root, CANARY_RULES)
    text = w.canary_rules(fid)
    try:
        old = p.read_text() if p.exists() else None
    except OSError as e:
        alert("check:wazuh", f"could not read {p} ({e.strerror or e})")
        return
    if old == text:
        return
    try:
        _put(p, text, 0o640, _owner(chown, "root", "wazuh"))
    except (SiteError, LookupError, OSError) as e:
        alert("check:wazuh", f"could not write the canary Wazuh rule {p}: {_clean(e, 160)}")
        return
    r = run(["/var/ossec/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        try:
            if old is None:
                p.unlink()
            else:
                _put(p, old, 0o640, _owner(chown, "root", "wazuh"))
            back = "rolled back"
        except (SiteError, LookupError, OSError) as e:
            back = f"NOT rolled back ({_clean(e, 80)}): fix {p} before restarting Wazuh"
        alert("check:wazuh", f"the canary Wazuh rule failed wazuh-analysisd -t; {back}: "
                             f"{_clean((r.stderr or r.stdout or '').strip(), 160)}")
        return
    r = run(["systemctl", "restart", "wazuh-manager"], capture_output=True, text=True)
    if r.returncode != 0:
        alert("check:wazuh", "wazuh-manager did not restart after the canary rule changed: "
                             f"{_clean((r.stderr or '').strip(), 160)}")


def check(root, run, sql=None, api=None, occ=None, now=None, chown=None):
    """`chp-site documents check` (chp-documents-check.timer, nightly): every check below, then one result file
    (CHECK_RESULT, 0600) that monitor check 81 and the daily review read. Returns the lines to print; any line that
    starts with ALERT means a failure (the command then exits 1). One run at a time (CHECK_LOCK). SIGTERM (a stop or a
    timeout) raises SystemExit, so the canary's clean-up still runs; ExecStopPost=canary-off is the second net."""
    import fcntl
    import signal
    root = Path(root)
    c = _kv(_p(root, CONF))
    if not c:
        return ["OK documents: not enabled on this host (nothing to check)"]
    if c.get("ENABLED") != "yes":
        return ["OK documents: enable has not finished on this host (ENABLED is not yes); nightly check not run"]
    fd = _lock(root)
    if fd is None:
        return ["OK NextCloud check: another check is running; this one was not started"]

    def term(signum, frame):
        raise SystemExit(128 + signum)
    try:
        old = signal.signal(signal.SIGTERM, term)
    except ValueError:                                # not the main thread: no handler (ExecStopPost still cleans)
        old = None
    try:
        return _check(root, c, run, sql or sql_runner(run), api or https_api(c), occ or occ_run,
                      int(now() if now else time.time()), chown)
    finally:
        if old is not None:
            signal.signal(signal.SIGTERM, old)
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _check(root, c, run, sql, api, occ, t, chown):
    alerts = []

    def alert(key, text):
        k = _clean(key, 80)
        if all(a["key"] != k for a in alerts):        # one alert per key
            alerts.append({"key": k, "text": _clean(text, 400)})

    ids = {}
    for n in CONTROLLED + OPEN:
        v = c.get(f"{n.upper()}_FOLDER_ID", "")
        ids[n] = v if re.fullmatch(r"[1-9][0-9]*", v) else None
    db = folders = tagid = None
    storages, counts = {}, {}
    try:
        db = {"folders": sql(Q_FOLDERS), "groups": sql(Q_GROUPS), "tags": sql(Q_TAGS), "app": sql(Q_APP)}
        folders, tagid = _policy(db, ids, alert)
        storages = _storages(folders, ids, alert)
    except (SiteError, ValueError, TypeError, AttributeError) as e:
        alert("check:sql", f"the tag check could not read NextCloud's database: {_clean(e, 200)}")
        db = None
    try:                                              # runtime drift: NextCloud rewrote config.php after enable
        tf = _p(root, "etc/fapolicyd/trust.d/nextcloud")
        entry, have = _trust_entry(tf, CONFIG_PHP), _size_sha(_p(root, CONFIG_PHP))
        if have is None:
            alert("trust", f"{CONFIG_PHP} is missing")
        elif entry is None:
            alert("trust", f"{CONFIG_PHP} has no single valid fapolicyd trust entry in {tf} (none, malformed or "
                           "duplicated): re-run chp-site documents enable")
        elif entry != have:
            alert("trust", f"{CONFIG_PHP} does not match its fapolicyd trust entry (size/sha256): NextCloud changed it "
                           "since the last enable; check the change, then re-run chp-site documents enable")
    except SiteError as e:
        alert("trust", str(e))

    def ready():                                      # the canary file exists: positive control, then its rule
        st, tag = storages.get("CUI"), (tagid or {}).get("CUI")
        if db is None or st is None or tag is None:
            alert("check:control", "positive control not run: the CUI folder's storage or the CUI tag is unknown")
            return
        try:
            rows = sql(q_control(st, tag))
        except SiteError as e:
            alert("check:control", f"positive control could not read the database: {_clean(e, 160)}")
            return
        if not rows:
            alert("check:control", f"positive control FAILED: the canary file {CANARY_FILE} was not found in the CUI "
                                   "folder's storage with the CUI tag by the tag check's own filter (path, storage or "
                                   "tag assumptions wrong, or the file is untagged): the tag check cannot be trusted")
            return
        _canary_rules(root, run, int(rows[0]["fileid"]), alert, chown)

    canary = _canary(occ, api, alert, ready)          # before the share check, which also proves the canary cleaned up
    if db is not None:
        try:
            counts = _files(sql, folders, ids, tagid, storages, alert)
        except (SiteError, ValueError, TypeError, AttributeError) as e:
            alert("check:sql", f"the tag check could not read NextCloud's files: {_clean(e, 200)}")
    md5 = md5_state(run)
    degraded = md5.startswith("DEGRADED")
    _write_result(root, {"version": 1, "epoch": t, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)),
                         "ok": not alerts, "alerts": alerts, "degraded": degraded, "md5": md5, "canary": canary,
                         "counts": counts})
    lines = [f"ALERT NextCloud check: {a['text']}" for a in alerts]
    if not alerts:
        lines.append("OK NextCloud check: every file in CUI, FCI and Archive tagged, no untagged CUI_/FCI_ file, policy "
                     "as required; share canary refused (public link, internal share)")
    lines.append(md5)
    return lines
