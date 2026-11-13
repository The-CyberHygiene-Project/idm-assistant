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
SITE_ROOT_CA = "/etc/pki/ca-trust/source/anchors/chp-root.crt"
CERT = "etc/pki/nextcloud/chain.pem"
FSMARK_PENDING = "var/lib/chp/fapolicyd-restart-pending"
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
    return True


def _kv(path):
    if not path.exists():
        return {}
    return dict(ln.split("=", 1) for ln in path.read_text().splitlines() if "=" in ln and not ln.startswith("#"))


def conf_text(fqdn, server_ip, days, ids):
    """/etc/chp/documents.conf (0644, no secrets): read by the checks (77-79, Plan 2 Task 6), the units and Plan 3."""
    lines = ["# written by chp-site documents enable; no secrets here", "ENABLED=yes", f"FQDN={fqdn}",
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

    # 1. packages (the signed chp repo). The fapolicyd restart comes at the very end, never inside a transaction.
    run(["dnf", "-y", "--enablerepo=chp", "module", "enable", "php:8.3", "postgresql:16"], capture_output=True, text=True)
    if not all(_ok(run, ["rpm", "-q", p]) for p in PACKAGES):
        run(["dnf", "-y", "--enablerepo=chp", "install", *PACKAGES], check=True)
    step("packages", "packages: nextcloud-chp, chp-documents (PHP 8.3, PostgreSQL 16, httpd from Rocky)")
    mta = [m for m in MTAS if _ok(run, ["rpm", "-q", m])]
    if mta:
        raise SiteError(f"a mail server is installed ({', '.join(mta)}): NextCloud's mail is off, but the apache user "
                        "could relay through a local MTA's socket, which the egress table cannot see. Remove it "
                        f"(dnf remove {' '.join(mta)}), then re-run chp-site documents enable")
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
        _put(zp, zone(site, hosts, serial), 0o640, _owner(chown, "root", "named"))
        run(["named-checkzone", d, str(zp)], check=True, capture_output=True, text=True)
        run(["rndc", "reload", d], check=True, capture_output=True, text=True)
    step("dns", f"DNS: {fqdn} IN A {sip} in the site zone")

    # 3. site-rendered web and egress files (chp-documents ships them failing closed)
    web_changed = _put(_p(root, LAN_INC), f"Require ip {cidr}\n", 0o644)
    web_changed |= _put(_p(root, EGRESS_ADDR), f"define CHP_NC_SERVER_IP = {sip}\n", 0o644)
    cp = _p(root, CONF)
    ids = {n: _kv(cp)[f"{n.upper()}_FOLDER_ID"] for n in CONTROLLED + OPEN if f"{n.upper()}_FOLDER_ID" in _kv(cp)}
    days = site.get("DOCUMENTS_BACKUP_DAYS", 14)
    _put(cp, conf_text(fqdn, sip, days, ids), 0o644)
    step("render", f"rendered: LAN-only httpd ({cidr}), egress address {sip}, /etc/chp/documents.conf")
    run(["systemctl", "daemon-reload"], check=True)
    run(["systemctl", "enable", "--now", "chp-nextcloud-egress.service"], check=True)
    step("egress", "egress table inet chp_nextcloud_egress loaded (apache: this server only, no DNS)")

    # 4. database: PostgreSQL 16, Unix socket, peer authentication
    pgd = _p(root, PGDATA)
    if not (pgd / "PG_VERSION").exists():
        run(["postgresql-setup", "--initdb"], check=True, capture_output=True, text=True)
    pc = pgd / "postgresql.conf"
    text = pc.read_text() if pc.exists() else ""
    new = re.sub(r"^#?\s*listen_addresses\s*=.*$", "listen_addresses = ''", text, flags=re.M)
    if "listen_addresses = ''" not in new:
        new += ("" if new.endswith("\n") or not new else "\n") + "listen_addresses = ''\n"
    pg_changed = _put(pc, new, 0o600, _owner(chown, "postgres", "postgres"))
    pg_changed |= _put(pgd / "pg_hba.conf", PG_HBA, 0o600, _owner(chown, "postgres", "postgres"))
    run(["systemctl", "enable", "--now", "postgresql"], check=True)
    if pg_changed:
        run(["systemctl", "restart", "postgresql"], check=True)
    psql = ["runuser", "-u", "postgres", "--", "psql", "-qtA", "-c"]
    if _out(run, psql + ["SELECT 1 FROM pg_roles WHERE rolname='apache'"]).strip() != "1":
        run(psql + ["CREATE ROLE apache LOGIN"], check=True, capture_output=True, text=True)
    if _out(run, psql + ["SELECT 1 FROM pg_database WHERE datname='nextcloud'"]).strip() != "1":
        run(psql + ["CREATE DATABASE nextcloud OWNER apache TEMPLATE template0 ENCODING 'UTF8'"], check=True,
            capture_output=True, text=True)
    step("database", "database: PostgreSQL 16, socket only, peer authentication, database nextcloud (owner apache)")

    # 5. NextCloud installed offline (no admin on the command line), data on /data
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
    if not (tf.exists() and "/etc/nextcloud/config.php" in tf.read_text()):
        run(["fapolicyd-cli", "--file", "add", "/etc/nextcloud/config.php", "--trust-file", "nextcloud"], check=True)
        run(["fapolicyd-cli", "--update"], check=True)
    step("install", f"NextCloud installed offline (data {DATA}/data)")

    # 6. settings: offline, hardening, logs; bcrypt (FIPS breaks PHP Argon2id) before any local account
    occ("config:system:set", "hashing_default_password", "--type=boolean", "--value=true")
    for keys, value, typ in _system(fqdn):
        occ("config:system:set", *keys, *([f"--type={typ}"] if typ else []), f"--value={value}")
    occ("background:cron")
    for app, key, value in SHARING:
        occ("config:app:set", app, key, f"--value={value}")
    step("settings", "settings: no internet connection, app store and update checker off, mail off, "
                     f"trusted domain {fqdn}, {origin}, sharing locked down")

    # 7. apps: exactly what the design needs on; editors and outbound features off
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
    _audit_log(root, chown)

    # 8. break-glass admin (bcrypt; /login?direct=1); its secret escrowed, never printed or logged
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

    # 9. Kanidm: groups and the OIDC client (ES256, PKCE S256, chp_groups claim)
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

    # 10. NextCloud -> Kanidm: SELinux relay (the egress table limits where), the site CA, the provider
    if "--> on" not in _out(run, ["getsebool", "httpd_can_network_relay"]):
        run(["setsebool", "-P", "httpd_can_network_relay", "on"], check=True)
    if "chp-root.crt" not in occ("security:certificates")[1]:
        occ("security:certificates:import", SITE_ROOT_CA)
    provs = occ.json("user_oidc:provider", "--output=json")
    names = {p.get("identifier") for p in (provs if isinstance(provs, list) else provs.values() if isinstance(provs, dict)
                                           else []) if isinstance(p, dict)}
    if "kanidm" not in names:
        occ("user_oidc:provider", "kanidm", f"--clientid={CLIENT}", f"--clientsecret-file={OIDC_SECRET}",
            f"--discoveryuri=https://idm.{d}/oauth2/openid/{CLIENT}/.well-known/openid-configuration",
            "--scope=openid profile email groups", "--unique-uid=0", "--mapping-uid=preferred_username",
            "--mapping-display-name=name", "--mapping-email=email", "--mapping-groups=chp_groups",
            "--group-provisioning=1", "--group-whitelist-regex=^(cui-users|doc-reviewers|chp-users)$",
            "--check-bearer=0", "--send-id-token-hint=1")
    step("oidc", "sign-in: user_oidc provider kanidm; the login page goes straight to Kanidm")

    # 11. groups, team folders, ACLs
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
    step("folders", "team folders: " + ", ".join(f"{n}={ids[n]}" for n in CONTROLLED + OPEN)
         + "; share off on CUI/FCI/Archive; reviewers read-only there")

    # 12. tags by folder + containment (owner decision 3)
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
    _put(cp, conf_text(fqdn, sip, days, ids), 0o644)
    step("tags", f"tags: CUI folder and Archive -> CUI, FCI -> FCI; copy/move out refused except CUI <-> Archive")

    # 13. web: LAN-only firewall, certificate, services
    rich = f'rule family="ipv4" source address="{cidr}" port port="{PORT}" protocol="tcp" accept'
    if rich not in _out(run, ["firewall-cmd", "--permanent", "--list-rich-rules"]).splitlines():
        run(["firewall-cmd", "-q", "--permanent", "--add-rich-rule", rich], check=True)
        run(["firewall-cmd", "-q", "--reload"], check=True)
    cert_new = not _p(root, CERT).exists()
    if cert_new:
        run(["/usr/libexec/chp/cert-renew-nextcloud", "--issue"], check=True)
    step("cert", f"certificate for {fqdn} from the site CA (renewed by chp-nextcloud-cert-renew.timer)")
    run(["systemctl", "enable", "--now", *UNITS], check=True)
    if web_changed or cert_new:
        run(["systemctl", "restart", "php-fpm", "httpd"], check=True)
    step("services", f"started: {', '.join(UNITS)} (HTTPS {PORT}, LAN {cidr} only)")

    # 14. Wazuh: the audit log and the rules (checked before the manager restarts; a bad rule stops it)
    _wazuh(root, run, chown)
    step("wazuh", "Wazuh: NextCloud audit log read; rules 100600-100630 (share/contain/app-off/tag/egress at 12)")

    # 15. fapolicyd: AFTER every package and file change (never in an rpm scriptlet)
    run(["fapolicyd-cli", "--file", "update", "/etc/nextcloud/config.php", "--trust-file", "nextcloud"], check=False,
        capture_output=True, text=True)
    run(["systemctl", "restart", "fapolicyd"], check=True)
    _p(root, FSMARK_PENDING).unlink(missing_ok=True)        # chp-base's fsmark change is applied by this restart
    denied = next((ln.strip() for ln in _out(run, ["fapolicyd-cli", "--check-status"]).splitlines()
                   if ln.strip().startswith("Denied")), "Denied accesses: unknown")
    step("fapolicyd", f"fapolicyd restarted (rule 65 loaded); {denied}")

    # 16. escrow, AIDE
    if pend.exists():
        if stick is not None:
            from .escrow import move_documents_secrets
            move_documents_secrets(pending / "documents", stick, now())
            step("escrow", "break-glass secret written to the site stick (escrow/), read back, shredded here")
        else:
            step("escrow", "break-glass secret is in the pending folder: plug in the site stick and run "
                           "chp-site export-client")
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
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"# NextCloud break-glass admin (sign in at /login?direct=1)\nNEXTCLOUD_ADMIN_USER={ADMIN}\n"
                f"NEXTCLOUD_ADMIN_PASSWORD={pw}\n")
        f.flush()
        os.fsync(f.fileno())
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
    changed = _put(rules, w.NEXTCLOUD_RULES, 0o640, grp)
    changed |= _put(conf, w.documents_manager(old_conf), 0o640, grp)
    if not changed:
        return
    r = run(["/var/ossec/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if r.returncode != 0:
        if old_rules is None:
            rules.unlink()
        else:
            _put(rules, old_rules, 0o640, grp)
        _put(conf, old_conf, 0o640, grp)
        raise SiteError("the Wazuh rule check (wazuh-analysisd -t) failed on the NextCloud rules; the old rules are "
                        "back and the manager was not restarted: " + (r.stderr or r.stdout or "").strip()[:200])
    run(["systemctl", "restart", "wazuh-manager"], check=True)


def status(root, run):
    """Lines for `chp-site documents status` (and the nightly check, §12)."""
    c = _kv(_p(root, CONF))
    if c.get("ENABLED") != "yes":
        return ["documents: not enabled on this host (chp-site documents enable, on the server)"]
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
