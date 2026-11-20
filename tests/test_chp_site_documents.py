"""chp-site documents enable|status (ISO 0.7.0 Plan 2 Task 5): every command goes through injected fakes (run, occ, a
Kanidm with a fake CLI); nothing here touches a real system."""
import json
import os
import re
from pathlib import Path

import pytest

from chp_site import documents as D
from chp_site.hosts import parse_hosts
from chp_site.kanidm import Kanidm
from chp_site.sitefile import SiteError, parse_site
from tests.test_chp_site_hosts import HOSTS
from tests.test_chp_site_sitefile import GOOD

FX = Path(__file__).parent / "fixtures" / "wazuh"
SITE = parse_site(GOOD + "SECURITY_ADDONS=yes\nDOCUMENTS=yes\n")
HS = parse_hosts(HOSTS, SITE)
SRV, CLI = "iso2-srv", "iso2-cli"
FQDN = "files.iso2.lab.test"
OIDC_SECRET = "oidc-client-secret-value-0123456789"


class R:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class Run:
    """The host: records every argv; answers the few queries enable makes."""
    def __init__(self, root, mta=False):
        self.root, self.calls, self.kw = root, [], []
        self.pg_role = self.pg_db = False
        self.rich, self.sebool, self.mta, self.pkgs = set(), False, mta, set()
        self.pgver, self.fail_restart, self.wazuh_active = "16.13", None, True
        # fapolicyd: the n-th restarts (1-based) in fapo_dies leave the daemon dead ~1 s later ("recvmesg failed",
        # lab round 3 D6); a dead daemon answers no --check-status counter; no_counter: alive but no counter line
        self.fapo_dies, self.fapo_restarts, self.no_counter, self.fsmark_rc = set(), 0, False, 0
        self.fsmark_warn = ""                              # fsmark --verify restarted fapolicyd itself (exit 0 + warning)
        self.enabled_units = set()                         # systemctl enable / is-enabled
        self.nc = None                                     # set by Env: the area lookup reads what occ scanned
        self.fileids = {}                                  # (folder id, path in filecache) -> fileid

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        self.kw.append(kw)
        j = " ".join(argv)
        if argv[:3] == ["rpm", "-q", "--qf"]:
            return R(0, self.pgver)
        if argv[:2] == ["rpm", "-q"]:
            pk = argv[-1]
            if pk in ("postfix", "sendmail", "exim", "opensmtpd"):
                return R(0 if self.mta and pk == "postfix" else 1, "" if self.mta else f"package {pk} is not installed")
            return R(0 if pk in self.pkgs else 1, pk)
        if argv[:1] == ["dnf"] and "install" in argv:
            self.pkgs.update(x for x in argv if not x.startswith("-") and x not in ("dnf", "install"))
            return R()
        if argv[:1] == ["postgresql-setup"]:
            d = self.root / "var/lib/pgsql/data"
            d.mkdir(parents=True, exist_ok=True)
            (d / "PG_VERSION").write_text("16\n")
            (d / "postgresql.conf").write_text("#listen_addresses = 'localhost'\nport = 5432\n")
            (d / "pg_hba.conf").write_text("local all all trust\n")
            return R()
        if argv[:2] == ["install", "-d"]:
            skip = False
            for x in argv[2:]:
                if skip:
                    skip = False
                elif x in ("-m", "-o", "-g"):
                    skip = True
                elif not x.startswith("-"):
                    (self.root / x.lstrip("/")).mkdir(parents=True, exist_ok=True)
            return R()
        if "psql" in argv and "oc_filecache" in j and "g.folder_id" in j:
            # the Compliance-area lookup: a folder on the disk that groupfolders:scan has seen has a fileid
            m = re.search(r"g\.folder_id = (\d+) AND f\.path = '([^']+)'", j)
            fid, path = int(m.group(1)), m.group(2)
            disk = self.root / f"data/nextcloud/data/__groupfolders/{fid}" / path
            rows = []
            if disk.is_dir() and self.nc is not None and fid in self.nc.scanned:
                k = (fid, path)
                self.fileids.setdefault(k, 500 + len(self.fileids))
                rows = [{"fileid": self.fileids[k]}]
            return R(0, json.dumps(rows) + "\n")
        if "psql" in argv:
            if "pg_roles" in j:
                return R(0, "1\n" if self.pg_role else "")
            if "pg_database" in j:
                return R(0, "1\n" if self.pg_db else "")
            if "CREATE ROLE" in j:
                self.pg_role = True
            if "CREATE DATABASE" in j:
                self.pg_db = True
            if "MD5" in j:
                return R(0, D.MD5_CHP + "\n")
            return R()
        if argv[:1] == ["firewall-cmd"]:
            if "--list-rich-rules" in argv:
                return R(0, "\n".join(sorted(self.rich)))
            if "--add-rich-rule" in argv:
                self.rich.add(argv[argv.index("--add-rich-rule") + 1])
            return R()
        if argv[:1] == ["getsebool"]:
            return R(0, f"httpd_can_network_relay --> {'on' if self.sebool else 'off'}\n")
        if argv[:1] == ["setsebool"]:
            self.sebool = True
            return R()
        if argv[:1] == ["/usr/libexec/chp/cert-renew-nextcloud"]:
            p = self.root / "etc/pki/nextcloud"
            p.mkdir(parents=True, exist_ok=True)
            (p / "chain.pem").write_text("CERT")
            (p / "key.pem").write_text("KEY")
            return R()
        if argv[:2] == ["fapolicyd-cli", "--file"] and argv[2] in ("add", "update"):
            # fapolicyd records "<path> <size> <sha256>" of the file as it is at that moment
            import hashlib
            t = self.root / "etc/fapolicyd/trust.d/nextcloud"
            t.parent.mkdir(parents=True, exist_ok=True)
            f = self.root / argv[3].lstrip("/")
            b = f.read_bytes() if f.exists() else b""
            lines = [ln for ln in (t.read_text().splitlines() if t.exists() else []) if ln.split()[:1] != [argv[3]]]
            t.write_text("\n".join(lines + [f"{argv[3]} {len(b)} {hashlib.sha256(b).hexdigest()}"]) + "\n")
            return R()
        if argv[:2] == ["fapolicyd-cli", "--check-status"]:
            if self.fapo_dead() or self.no_counter:
                return R(1, "", "")
            return R(0, "Allowed accesses: 100\nDenied accesses: 0\n")
        if argv[:2] == ["systemctl", "is-active"]:
            if argv[-1] == "wazuh-manager" and not self.wazuh_active:
                return R(3, "inactive\n")
            if argv[-1] == "fapolicyd" and self.fapo_dead():
                return R(3, "failed\n")
            return R(0, "active\n")
        if argv[:2] == ["systemctl", "is-enabled"]:
            return R(0, "enabled\n") if argv[-1] in self.enabled_units else R(1, "disabled\n")
        if argv[:2] == ["systemctl", "enable"]:
            self.enabled_units.update(x for x in argv[2:] if not x.startswith("-"))
        if argv == ["systemctl", "restart", "fapolicyd"]:
            self.fapo_restarts += 1
        if argv == ["/usr/libexec/chp/fapolicyd-fsmark", "--verify"]:
            return R(self.fsmark_rc, "", "chp-fapolicyd-fsmark: fapolicyd is NOT active after a restart" if self.fsmark_rc
                     else self.fsmark_warn)
        if argv[:2] == ["systemctl", "restart"] and self.fail_restart and self.fail_restart in argv:
            if kw.get("check"):
                import subprocess
                raise subprocess.CalledProcessError(1, argv)
            return R(1)
        return R()

    def fapo_dead(self):
        return self.fapo_restarts in self.fapo_dies


DEFAULT_APPS = {"files", "dav", "viewer", "files_pdfviewer", "text", "firstrunwizard", "recommendations", "dashboard",
                "photos", "federatedfilesharing", "updatenotification", "weather_status", "systemtags", "workflowengine",
                "appstore", "office"}
DENIED = "fopen(/usr/lib/nextcloud/config/config.php): Failed to open stream: Operation not permitted"


def _trusted(root):
    """fapolicyd (integrity = none): php may read config.php only while trust.d/nextcloud holds a valid entry for it."""
    return any(x is not None for x in D._trust_lines(root / "etc/fapolicyd/trust.d/nextcloud", D.CONFIG_PHP))


class NC:
    """A NextCloud as occ sees it."""
    def __init__(self):
        self.installed, self.sysconf, self.appconf = False, {}, {}
        self.enabled = set(DEFAULT_APPS)
        self.users, self.groups, self.folders, self.tags = set(), {"admin"}, {}, {}
        self.providers, self.certs, self.calls, self.envs = set(), set(), [], []
        self.sticky_groups = False
        self.scanned, self.provider_ids, self.provider_args = set(), {}, {}
        self.root = None                                  # set by Env: config.php is written like NextCloud does

    def _cfg(self):
        if self.root is not None:
            c = self.root / "etc/nextcloud/config.php"
            c.parent.mkdir(parents=True, exist_ok=True)
            c.write_text("<?php $CONFIG = " + json.dumps(sorted(map(list, self.sysconf.items()))) + ";\n")

    def __call__(self, argv, env=None):
        argv = list(argv)
        self.calls.append(argv)
        self.envs.append(env)
        c, a = argv[0], argv[1:]
        cfg = self.root / "etc/nextcloud/config.php" if self.root is not None else None
        # fapolicyd's %languages rule: an untrusted config.php cannot be read back by php (lab round 2, D3)
        if cfg is not None and cfg.exists() and not _trusted(self.root):
            return 1, "", DENIED
        if c == "status":
            return 0, json.dumps({"installed": self.installed}), ""
        if c == "maintenance:install":
            if cfg is not None and not cfg.exists():
                return 1, "", "Can't write into config directory!"     # the RPM ships no config.php
            self._cfg()                                                  # written, then read back
            if not _trusted(self.root):
                return 1, "", DENIED
            self.installed = True
            self._cfg()
            return 0, "Nextcloud was successfully installed", ""
        if not self.installed and c not in ("status",):
            return 1, "", "Nextcloud is not installed"
        if c == "config:system:set":
            keys = [x for x in a if not x.startswith("--")]
            val = next((x.split("=", 1)[1] for x in a if x.startswith("--value=")), None)
            self.sysconf[tuple(keys)] = val
            self._cfg()
            return 0, "", ""
        if c == "config:app:set":
            keys = [x for x in a if not x.startswith("--")]
            val = next((x.split("=", 1)[1] for x in a if x.startswith("--value=")), None)
            self.appconf[tuple(keys)] = val
            return 0, "", ""
        if c == "app:list":
            return 0, json.dumps({"enabled": {x: "1.0" for x in sorted(self.enabled)}, "disabled": {}}), ""
        if c == "app:enable":
            self.enabled.add(a[0])
            return 0, "", ""
        if c == "app:disable":
            if a[0] in D.ALWAYS_ENABLED:
                return 1, "", f"{a[0]} can't be disabled."                # NextCloud 35 core/shipped.json (D4)
            self.enabled.discard(a[0])
            return 0, "", ""
        if c == "user:info":
            return (0, "ok", "") if a[0] in self.users else (1, "", "user not found")
        if c == "user:add":
            assert env and env.get("OC_PASS")
            self.users.add(a[-1])
            return 0, "", ""
        if c == "group:list":
            return 0, json.dumps({g: [] for g in sorted(self.groups)}), ""
        if c == "group:add":
            self.groups.add(a[0])
            return 0, "", ""
        if c == "groupfolders:list":
            bits = {"read": 1, "write": 6, "delete": 8, "share": 16}
            return 0, json.dumps([{"id": i, "mount_point": f["name"], "acl": f["acl"],
                                   "groups": {g: sum(bits[x] for x in p) for g, p in f["groups"].items()}}
                                  for i, f in sorted(self.folders.items())]), ""
        if c == "groupfolders:create":
            i = len(self.folders) + 1
            self.folders[i] = {"name": a[0], "groups": {}, "acl": False, "rules": []}
            return 0, f"{i}\n", ""
        if c == "groupfolders:group":
            if "--delete" in a:
                if not self.sticky_groups:
                    self.folders[int(a[0])]["groups"].pop(a[1], None)
            else:
                self.folders[int(a[0])]["groups"][a[1]] = a[2:]
            return 0, "", ""
        if c == "groupfolders:permissions":
            f = self.folders[int(a[0])]
            if "--enable" in a:
                f["acl"] = True
            elif a[-1] == "clear":                                       # groupfolders: drop that mapping's rule
                f["rules"] = [r for r in f["rules"] if r[:2] != a[1:3]]
            else:
                f["rules"].append(a[1:])
            return 0, "", ""
        if c == "tag:list":
            return 0, json.dumps({str(i): {"name": t[0], "access": t[1]} for i, t in self.tags.items()}), ""
        if c == "tag:add":
            self.tags[len(self.tags) + 1] = (a[0], a[1])
            return 0, "Tag added", ""
        if c == "user_oidc:provider":
            if a == ["--output=json"]:
                return 0, json.dumps([{"identifier": p} for p in sorted(self.providers)]), ""
            if not a:                                                    # the table occ prints (spike logs/44)
                rows = "".join(f"| {i:<2} | {p:<10} | https://idm/oauth2/openid/x/.well-known/openid-configuration "
                               f"|  | x |\n" for p, i in sorted(self.provider_ids.items(), key=lambda x: x[1]))
                return 0, ("+----+------------+\n| ID | Identifier | Discovery endpoint | End session endpoint | "
                           "Client ID |\n+----+------------+\n" + rows + "+----+------------+\n"), ""
            self.providers.add(a[0])
            self.provider_ids.setdefault(a[0], len(self.provider_ids) + 1)
            self.provider_args[a[0]] = a[1:]
            return 0, "", ""
        if c == "groupfolders:scan":
            self.scanned.add(int(a[0]))
            return 0, "", ""
        if c == "security:certificates":
            return 0, "\n".join(sorted(self.certs)), ""
        if c == "security:certificates:import":
            self.certs.add(os.path.basename(a[0]))
            return 0, "", ""
        return 0, "", ""


class KanidmCli:
    """kanidm as `Kanidm(run=...)` calls it: (argv) -> (rc, out, err)."""
    def __init__(self):
        self.groups, self.clients, self.calls = {"chp_users"}, {}, []
        self.public, self.attrs, self.persons = set(), {}, set()

    def _set(self, name, k, v, add=False):
        a = self.attrs.setdefault(name, {})
        if add:
            a.setdefault(k, [])
            if v not in a[k]:
                a[k].append(v)
        else:
            a[k] = [v]

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        a = argv[:-2]                                  # drop -D idm_admin
        if a[:2] == ["group", "get"]:
            return (0, f"name: {a[2]}\n", "") if a[2] in self.groups else (0, f"No matching group '{a[2]}'\n", "")
        if a[:2] == ["group", "create"]:
            self.groups.add(a[2])
            return 0, "", ""
        if a[:2] == ["person", "get"]:                 # Kanidm 1.11.2: absence is on STDOUT with rc 0 (Plan 2 9c)
            return (0, f"---\nname: {a[2]}\ndisplayname: {a[2]}\n", "") if a[2] in self.persons \
                else (0, "No matching entries\n", "")
        if a[:3] == ["system", "oauth2", "get"]:
            if a[3] not in self.clients:
                return 0, "No matching entries\n", ""
            cls = ["oauth2_resource_server"] + (["oauth2_resource_server_public"] if a[3] in self.public
                                                else ["oauth2_resource_server_basic"])
            extra = "".join(f"{k}: {v}\n" for k, vs in sorted(self.attrs.get(a[3], {}).items()) for v in vs)
            return 0, "".join(f"class: {c}\n" for c in cls) + f"name: {a[3]}\ndisplayname: NextCloud\n" + extra, ""
        if a[:3] == ["system", "oauth2", "create"]:
            self.clients[a[3]] = a[4:]
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "create-public"]:
            self.clients[a[3]] = a[4:]
            self.public.add(a[3])
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "enable-localhost-redirects"]:
            self._set(a[3], "oauth2_allow_localhost_redirect", "true")
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "add-redirect-url"]:
            self._set(a[3], "oauth2_rs_origin", a[4], add=True)
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "set-refresh-token-expiry"]:
            self._set(a[3], "oauth2_refresh_token_expiry", a[4])
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "show-basic-secret"]:
            return 0, f"{OIDC_SECRET}\n", ""
        return 0, "", ""


def make_root(tmp_path, security=True):
    r = tmp_path / "root"
    (r / "etc/chp").mkdir(parents=True)
    if security:
        (r / "etc/chp/security.conf").write_text("ROLE=server\nALERT_LEVEL=10\nRETENTION_DAYS=90\nDATA_DIR=/data/wazuh\n")
    (r / "var/named").mkdir(parents=True)
    (r / "var/named/iso2.lab.test.zone").write_text(
        "$TTL 300\n@ IN SOA iso2-srv.iso2.lab.test. hostmaster.iso2.lab.test. ( 2026110101 3600 600 86400 300 )\n"
        "@ IN NS iso2-srv.iso2.lab.test.\niso2-srv     IN A 192.168.100.30\nidm          IN A 192.168.100.30\n")
    (r / "var/ossec/etc/rules").mkdir(parents=True)
    (r / "var/ossec/etc/ossec.conf").write_text((FX / "manager-ossec.conf").read_text())
    (r / "etc/httpd/conf.d").mkdir(parents=True)
    (r / "etc/httpd/conf.d/chp-nextcloud-lan.inc").write_text("Require all denied\n")
    (r / "etc/hosts").write_text("127.0.0.1 localhost\n")
    (r / "etc/pki/ca-trust/source/anchors").mkdir(parents=True)
    (r / "var/log/nextcloud").mkdir(parents=True)
    return r


class Env:
    def __init__(self, tmp_path, security=True, mta=False):
        self.root = make_root(tmp_path, security)
        self.run, self.nc, self.kcli = Run(self.root, mta), NC(), KanidmCli()
        self.nc.root = self.root
        self.run.nc = self.nc
        self.k = Kanidm("idm_admin", run=self.kcli)
        self.records = []
        self.stick = tmp_path / "stick"
        self.stick.mkdir()
        self.pending = tmp_path / "pending"
        self.sleeps = []

    def enable(self, host=SRV, site=None, data_is_mount=True, stick="default"):
        return D.enable(host, dict(site or SITE), HS, run=self.run, occ=self.nc, kanidm=self.k, root=self.root,
                        record=lambda *a, **k: self.records.append((a, k)), data_is_mount=data_is_mount,
                        stick=self.stick if stick == "default" else stick, pending=self.pending,
                        chown=lambda *a: None, now=lambda: "20261113T120000Z", sleep=self.sleeps.append)


def occ_names(nc, name):
    return [c for c in nc.calls if c[0] == name]


# ---------- refusals ----------

def test_refused_without_documents_yes(tmp_path):
    e = Env(tmp_path)
    with pytest.raises(SiteError, match="DOCUMENTS"):
        e.enable(site={**SITE, "DOCUMENTS": "no"})
    assert e.run.calls == [] and e.nc.calls == [] and e.kcli.calls == []


def test_refused_without_security_addons(tmp_path):
    e = Env(tmp_path)
    with pytest.raises(SiteError, match="SECURITY_ADDONS=yes"):
        e.enable(site={**SITE, "SECURITY_ADDONS": "no"})
    assert e.run.calls == [] and e.nc.calls == []


def test_refused_before_security_enable(tmp_path):
    e = Env(tmp_path, security=False)
    with pytest.raises(SiteError, match="security enable"):
        e.enable()
    assert e.run.calls == []


def test_refused_without_data_mount(tmp_path):
    e = Env(tmp_path)
    with pytest.raises(SiteError, match="/data"):
        e.enable(data_is_mount=False)
    assert e.run.calls == [] and e.nc.calls == []


def test_refused_on_a_client(tmp_path):
    e = Env(tmp_path)
    with pytest.raises(SiteError, match="server"):
        e.enable(host=CLI)
    assert e.run.calls == [] and e.nc.calls == []


def test_refused_when_a_mail_server_is_installed(tmp_path):
    e = Env(tmp_path, mta=True)
    with pytest.raises(SiteError, match="postfix"):
        e.enable()
    assert e.nc.calls == []                                      # refused before NextCloud is touched


# ---------- the run ----------

def _index(seq, pred, what):
    for i, x in enumerate(seq):
        if pred(x):
            return i
    raise AssertionError(f"not found: {what}")


def test_enable_order(tmp_path):
    e = Env(tmp_path)
    done = e.enable()
    # one timeline across run / occ / kanidm / record
    tl = []
    e2 = Env(tmp_path / "b")
    run0, occ0, k0 = e2.run, e2.nc, e2.kcli
    rec = lambda n, f: (lambda *a, **k: (tl.append((n, list(a[0]))), f(*a, **k))[1])
    e2.k = Kanidm("idm_admin", run=rec("k", k0))
    D.enable(SRV, dict(SITE), HS, run=rec("run", run0), occ=rec("occ", occ0), kanidm=e2.k, root=e2.root,
             record=lambda *a, **k: tl.append(("rec", [a[0], a[1].get("step", "")])), data_is_mount=True,
             stick=e2.stick, pending=e2.pending, chown=lambda *a: None, now=lambda: "20261113T120000Z", sleep=lambda s: None)
    hosts_txt = (e2.root / "etc/hosts").read_text()
    assert FQDN in hosts_txt and "idm.iso2.lab.test" in hosts_txt
    i = lambda pred, what: _index(tl, pred, what)
    pkgs = i(lambda x: x[0] == "run" and x[1][:1] == ["dnf"] and "install" in x[1], "dnf install")
    hosts_rec = i(lambda x: x[0] == "rec" and x[1][1] == "hosts", "hosts step")
    egress = i(lambda x: x[0] == "run" and x[1][:3] == ["systemctl", "enable", "--now"]
               and "chp-nextcloud-egress.service" in x[1], "egress unit")
    initdb = i(lambda x: x[0] == "run" and x[1][:1] == ["postgresql-setup"], "initdb")
    install = i(lambda x: x[0] == "occ" and x[1][0] == "maintenance:install", "occ maintenance:install")
    inet = i(lambda x: x[0] == "occ" and x[1][:2] == ["config:system:set", "has_internet_connection"], "offline")
    apps_on = i(lambda x: x[0] == "occ" and x[1][0] == "app:enable", "app:enable")
    oauth = i(lambda x: x[0] == "k" and x[1][:3] == ["system", "oauth2", "create"], "oauth2 create")
    claim = i(lambda x: x[0] == "k" and x[1][:3] == ["system", "oauth2", "update-claim-map"], "claim map")
    grp = i(lambda x: x[0] == "occ" and x[1][0] == "group:add", "group:add")
    folders = i(lambda x: x[0] == "occ" and x[1][0] == "groupfolders:create", "groupfolders:create")
    acl = i(lambda x: x[0] == "occ" and x[1][0] == "groupfolders:permissions", "ACL")
    tagrule = i(lambda x: x[0] == "occ" and x[1][:3] == ["config:app:set", "chp_foldertag", "rules"], "tag rule")
    cert = i(lambda x: x[0] == "run" and x[1][:1] == ["/usr/libexec/chp/cert-renew-nextcloud"], "cert")
    backup = i(lambda x: x[0] == "run" and x[1][:3] == ["systemctl", "enable", "--now"]
               and "chp-nextcloud-backup.timer" in x[1], "backup timer")
    wz = i(lambda x: x[0] == "rec" and x[1][1] == "wazuh", "wazuh rules")
    fapo = i(lambda x: x[0] == "run" and x[1] == ["systemctl", "restart", "fapolicyd"], "fapolicyd restart")
    web = i(lambda x: x[0] == "run" and x[1][:3] == ["systemctl", "enable", "--now"] and "httpd" in x[1], "httpd")
    # ruling: Wazuh reads the audit log with the rules loaded BEFORE NextCloud is installed or serves anyone
    assert pkgs < hosts_rec < egress < wz < initdb < install < inet < apps_on < oauth < claim < grp < folders < acl \
        < tagrule < cert < backup < fapo
    assert wz < web and backup == web
    # offline install: no admin on the command line, the data on /data
    inst = next(x[1] for x in tl if x[0] == "occ" and x[1][0] == "maintenance:install")
    assert "--disable-admin-user" in inst and "/data/nextcloud/data" in inst and not any("admin-pass" in a for a in inst)
    sc = e.nc.sysconf
    assert sc[("has_internet_connection",)] == "false" and sc[("appstoreenabled",)] == "false"
    assert sc[("updatechecker",)] == "false" and sc[("trusted_domains", "0")] == FQDN
    assert sc[("overwrite.cli.url",)] == f"https://{FQDN}:8443" and sc[("overwritehost",)] == f"{FQDN}:8443"
    assert sc[("mail_smtpmode",)] == "null"
    assert ("trusted_domains", "1") not in sc
    # apps: exactly these on; editors and outbound apps off
    assert {c[1] for c in occ_names(e.nc, "app:enable")} == set(D.APPS_ON) - DEFAULT_APPS
    assert set(D.APPS_ON) <= e.nc.enabled
    assert {"text", "richdocuments", "onlyoffice"} <= set(D.APPS_OFF)
    assert not (set(D.APPS_OFF) & e.nc.enabled)
    assert {c[1] for c in occ_names(e.nc, "app:disable")} == set(D.APPS_OFF) & DEFAULT_APPS
    assert {"groupfolders", "files_accesscontrol", "user_oidc", "chp_foldertag", "admin_audit"} <= set(D.APPS_ON)
    # every MTA probed, none installed
    assert ["rpm", "-q", "postfix"] in e.run.calls
    assert any("mail" in d.lower() for d in done)


def test_written_files(tmp_path):
    e = Env(tmp_path)
    e.enable()
    r = e.root
    assert (r / "etc/httpd/conf.d/chp-nextcloud-lan.inc").read_text() == "Require ip 192.168.100.0/24\n"
    assert (r / "etc/chp/nextcloud-egress-addr.nft").read_text() == "define CHP_NC_SERVER_IP = 192.168.100.30\n"
    conf = dict(ln.split("=", 1) for ln in (r / "etc/chp/documents.conf").read_text().splitlines()
                if "=" in ln and not ln.startswith("#"))
    assert conf["ENABLED"] == "yes" and conf["FQDN"] == FQDN and conf["SERVER_IP"] == "192.168.100.30"
    ids = {n: i for i, f in e.nc.folders.items() for n in [f["name"]]}
    assert conf["CUI_FOLDER_ID"] == str(ids["CUI"]) and conf["FCI_FOLDER_ID"] == str(ids["FCI"])
    assert conf["ARCHIVE_FOLDER_ID"] == str(ids["Archive"]) and conf["INTERNAL_FOLDER_ID"] == str(ids["Internal"])
    assert conf["DOCUMENTS_BACKUP_DAYS"] == "14"
    assert oct((r / "etc/chp/documents.conf").stat().st_mode & 0o777) == "0o644"
    assert not [k for k in conf if "SECRET" in k or "PASS" in k] and OIDC_SECRET not in str(conf)
    zone = (r / "var/named/iso2.lab.test.zone").read_text()
    assert any(ln.split()[:4] == ["files", "IN", "A", "192.168.100.30"] for ln in zone.splitlines())
    assert "2026110102" in zone or "( 2026" in zone
    assert ["rndc", "reload", "iso2.lab.test"] in e.run.calls
    sec = r / "etc/nextcloud/oidc-secret"
    assert sec.read_text().strip() == OIDC_SECRET and oct(sec.stat().st_mode & 0o777) == "0o640"
    pg = (r / "var/lib/pgsql/data/pg_hba.conf").read_text()
    assert "local nextcloud apache peer" in pg and "host" not in pg.split("#")[-1]
    assert "listen_addresses = ''" in (r / "var/lib/pgsql/data/postgresql.conf").read_text()


def test_tag_rules_contain_and_allow(tmp_path):
    e = Env(tmp_path)
    e.enable()
    fid = {f["name"]: i for i, f in e.nc.folders.items()}
    tid = {t[0]: i for i, t in e.nc.tags.items()}
    assert {t[0]: t[1] for t in e.nc.tags.values()} == {"CUI": "restricted", "FCI": "restricted"}
    rules = json.loads(e.nc.appconf[("chp_foldertag", "rules")])
    assert rules == {str(fid["CUI"]): str(tid["CUI"]), str(fid["FCI"]): str(tid["FCI"]),
                     str(fid["Archive"]): str(tid["CUI"])}                  # Archive holds CUI
    assert sorted(json.loads(e.nc.appconf[("chp_foldertag", "contain")])) == sorted([fid["CUI"], fid["FCI"], fid["Archive"]])
    assert sorted(json.loads(e.nc.appconf[("chp_foldertag", "contain_allow")])) == sorted(
        [[fid["CUI"], fid["Archive"]], [fid["Archive"], fid["CUI"]]])


def test_team_folders_share_off_on_cui_fci_archive(tmp_path):
    e = Env(tmp_path)
    e.enable()
    by = {f["name"]: f for f in e.nc.folders.values()}
    assert set(by) == {"CUI", "FCI", "Archive", "Operations", "Internal", "Public"}
    for n in ("CUI", "FCI", "Archive"):
        assert by[n]["groups"] == {"cui-users": ["read", "write", "delete"]}       # no share, no other group
    for n in ("Operations", "Internal", "Public"):
        assert by[n]["groups"] == {"chp-users": ["read", "write", "delete", "share"]}
    assert all(f["acl"] for f in by.values())                                       # advanced permissions on
    assert e.nc.appconf[("core", "shareapi_allow_resharing")] == "no"
    assert e.nc.appconf[("files_sharing", "outgoing_server2server_share_enabled")] == "no"


def test_reviewers_read_only_only_on_cui_fci_archive(tmp_path):
    e = Env(tmp_path)
    e.enable()
    by = {f["name"]: f for f in e.nc.folders.values()}
    on_root = lambda n: [r for r in by[n]["rules"] if r[3] == "/"]     # the Compliance areas' rules: Plan 3 Task 2
    for n in ("CUI", "FCI", "Archive"):
        assert on_root(n) == [["--group", "doc-reviewers", "--", "/", "+read", "-write", "-create", "-delete",
                               "-share"]]
    for n in ("Operations", "Internal", "Public"):
        assert on_root(n) == []
    # a reviewer reaches CUI only through cui-users: doc-reviewers is never a folder group
    assert all("doc-reviewers" not in f["groups"] for f in by.values())


def test_groups_and_oidc(tmp_path):
    e = Env(tmp_path)
    e.enable()
    assert {"cui-users", "doc-reviewers"} <= e.kcli.groups
    assert {"cui-users", "doc-reviewers", "chp-users"} <= e.nc.groups
    kc = [c[:-2] for c in e.kcli.calls]
    assert ["system", "oauth2", "create", "nextcloud", "NextCloud", f"https://{FQDN}:8443"] in kc
    assert ["system", "oauth2", "add-redirect-url", "nextcloud", f"https://{FQDN}:8443/index.php/apps/user_oidc/code"] in kc
    assert ["system", "oauth2", "update-scope-map", "nextcloud", "chp_users", "openid", "profile", "email", "groups"] in kc
    for g, v in (("cui-users", "cui-users"), ("doc-reviewers", "doc-reviewers"), ("chp_users", "chp-users")):
        assert ["system", "oauth2", "update-claim-map", "nextcloud", "chp_groups", g, v] in kc
    assert ["system", "oauth2", "update-claim-map-join", "nextcloud", "chp_groups", "array"] in kc
    prov = next(c for c in e.nc.calls if c[0] == "user_oidc:provider" and c[1] == "kanidm")
    assert "--mapping-groups=chp_groups" in prov and "--clientsecret-file=/etc/nextcloud/oidc-secret" in prov
    assert "--discoveryuri=https://idm.iso2.lab.test/oauth2/openid/nextcloud/.well-known/openid-configuration" in prov
    assert "--group-whitelist-regex=^(cui-users|doc-reviewers|chp-users)$" in prov
    assert e.nc.appconf[("user_oidc", "allow_multiple_user_backends")] == "0"     # login goes straight to Kanidm
    assert not any(OIDC_SECRET in " ".join(c) for c in e.nc.calls + e.run.calls)


def test_oidc_client_with_legacy_crypto_is_refused(tmp_path):
    e = Env(tmp_path)
    e.kcli.clients["nextcloud"] = []
    orig = e.kcli.__class__.__call__

    def legacy(self, argv):
        if argv[:4] == ["system", "oauth2", "get", "nextcloud"]:
            return 0, "name: nextcloud\noauth2_jwt_legacy_crypto_enable: true\n", ""
        return orig(self, argv)
    e.kcli.__class__ = type("Legacy", (KanidmCli,), {"__call__": legacy})
    with pytest.raises(SiteError, match="legacy"):
        e.enable()


def test_breakglass_secret_escrowed_not_printed(tmp_path, capsys):
    e = Env(tmp_path)
    done = e.enable()
    add = [(c, env) for c, env in zip(e.nc.calls, e.nc.envs) if c[0] == "user:add" and c[-1] == "ncadmin"]
    assert len(add) == 1                     # (the appender's chp-publisher: test_publish_account_* in test_doc_ledger)
    argv, env = add[0]
    pw = env["OC_PASS"]
    assert len(pw) >= 24 and "--password-from-env" in argv and argv[-1] == "ncadmin" and "admin" in argv
    # bcrypt (FIPS breaks PHP Argon2id) is set before the account is made
    hb = _index(e.nc.calls, lambda c: c[:2] == ["config:system:set", "hashing_default_password"], "bcrypt")
    assert hb < _index(e.nc.calls, lambda c: c[0] == "user:add", "user:add")
    every_argv = [" ".join(c) for c in e.nc.calls + e.run.calls + e.kcli.calls]
    assert not any(pw in a for a in every_argv)
    assert pw not in "\n".join(done) and pw not in repr(e.records)
    out = capsys.readouterr()
    assert pw not in out.out + out.err
    esc = e.stick / "escrow" / f"{SRV}-nextcloud-admin.secret"
    assert f"NEXTCLOUD_ADMIN_PASSWORD={pw}" in esc.read_text() and oct(esc.stat().st_mode & 0o777) == "0o600"
    assert not (e.pending / "documents").exists() or not any((e.pending / "documents").iterdir())


def test_breakglass_without_stick_stays_pending(tmp_path):
    e = Env(tmp_path)
    done = e.enable(stick=None)
    p = e.pending / "documents" / f"{SRV}-nextcloud-admin.secret"
    assert p.exists() and oct(p.stat().st_mode & 0o777) == "0o600"
    assert any("export-client" in d for d in done)


def test_enable_is_idempotent(tmp_path):
    e = Env(tmp_path)
    e.enable()
    written = [e.root / p for p in ("etc/hosts", "etc/chp/documents.conf", "etc/chp/nextcloud-egress-addr.nft",
                                    "etc/httpd/conf.d/chp-nextcloud-lan.inc", "var/named/iso2.lab.test.zone",
                                    "etc/nextcloud/oidc-secret", "var/lib/pgsql/data/pg_hba.conf",
                                    "var/lib/pgsql/data/postgresql.conf", "var/ossec/etc/rules/chp_nextcloud_rules.xml",
                                    "var/ossec/etc/ossec.conf")]
    for p in written:
        os.utime(p, (1000, 1000))
    folders, tags = dict(e.nc.folders), dict(e.nc.tags)
    n_occ, n_run, n_k = len(e.nc.calls), len(e.run.calls), len(e.kcli.calls)
    e.enable()
    occ2, run2, k2 = e.nc.calls[n_occ:], e.run.calls[n_run:], e.kcli.calls[n_k:]
    creates = {"maintenance:install", "user:add", "group:add", "groupfolders:create", "tag:add",
               "security:certificates:import"}
    assert [c for c in occ2 if c[0] in creates] == []
    assert [c for c in occ2 if c[0] == "user_oidc:provider"]          # an upsert, applied every run (no drift)
    assert [c for c in k2 if "create" in c[:3]] == []
    assert [c for c in k2 if "show-basic-secret" in c] == []
    j = [" ".join(c) for c in run2]
    assert not [x for x in j if "CREATE ROLE" in x or "CREATE DATABASE" in x or x.startswith("postgresql-setup")
                or "--add-rich-rule" in x or x.startswith("setsebool") or "cert-renew-nextcloud" in x
                or x.startswith("rndc") or x.startswith("systemctl restart") or "fapolicyd-cli --file add" in x
                or x.startswith("dnf -y --enablerepo=chp install")]
    assert e.nc.folders == folders and e.nc.tags == tags
    for p in written:
        assert p.stat().st_mtime == 1000, f"{p} rewritten on a second run"


def test_enable_records_each_step(tmp_path):
    e = Env(tmp_path)
    e.enable()
    acts = [a[0] for a, _ in e.records]
    assert set(acts) == {"documents-enable"}
    first, last = e.records[0], e.records[-1]
    assert first[1].get("after") in (None, False) and last[1].get("after") is True
    assert len(e.records) > 10


def test_fapolicyd_restarted_after_everything_and_pending_marker_cleared(tmp_path):
    e = Env(tmp_path)
    m = e.root / "var/lib/chp/fapolicyd-restart-pending"
    m.parent.mkdir(parents=True)
    m.write_text("")
    done = e.enable()
    assert not m.exists()
    r = _index(e.run.calls, lambda c: c == ["systemctl", "restart", "fapolicyd"], "restart")
    assert all(c[:1] != ["dnf"] for c in e.run.calls[r:])
    assert _index(e.run.calls, lambda c: c[:2] == ["fapolicyd-cli", "--check-status"], "status") > r
    assert any("Denied accesses: 0" in d for d in done)


def test_aide_refresh_is_announced(tmp_path):
    e = Env(tmp_path)
    done = e.enable()
    assert any("aide-accept" in d for d in done)
    assert any(a[1].get("aide_refresh") == "needed" for a, _ in e.records)


def test_wazuh_reads_the_audit_log_and_rules_are_checked(tmp_path):
    e = Env(tmp_path)
    e.enable()
    conf = (e.root / "var/ossec/etc/ossec.conf").read_text()
    assert conf.count("<location>/var/log/nextcloud/audit.log</location>") == 1
    rules = (e.root / "var/ossec/etc/rules/chp_nextcloud_rules.xml").read_text()
    assert "chp.contain.refused" in rules
    t = _index(e.run.calls, lambda c: c[:1] == ["/var/ossec/bin/wazuh-analysisd"] and "-t" in c, "rule test")
    assert _index(e.run.calls, lambda c: c == ["systemctl", "restart", "wazuh-manager"], "restart") > t


def test_bad_wazuh_rules_are_rolled_back(tmp_path):
    e = Env(tmp_path)
    old = e.root / "var/ossec/etc/rules/chp_nextcloud_rules.xml"
    old.write_text("<group name='old'/>\n")
    base = e.run.__class__.__call__

    def bad(self, argv, **kw):
        if argv[:1] == ["/var/ossec/bin/wazuh-analysisd"]:
            self.calls.append(list(argv))
            return R(1, "", "rule error")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadRun", (Run,), {"__call__": bad})
    with pytest.raises(SiteError, match="Wazuh"):
        e.enable()
    assert old.read_text() == "<group name='old'/>\n"
    assert ["systemctl", "restart", "wazuh-manager"] not in e.run.calls



def test_wazuh_gets_the_document_ledger_decoder(tmp_path):              # Plan 3 Task 9: ledger lines are JSON
    from chp_site import wazuh as w
    e = Env(tmp_path)
    e.enable()
    dec = e.root / "var/ossec/etc/decoders" / w.DOCS_DECODERS_FILE
    assert dec.read_text() == w.DOCS_DECODERS and (dec.stat().st_mode & 0o777) == 0o640
    assert f"/var/ossec/etc/decoders/{w.DOCS_DECODERS_FILE}" in D._aide_files("lab.test")
    t = _index(e.run.calls, lambda c: c[:1] == ["/var/ossec/bin/wazuh-analysisd"] and "-t" in c, "rule test")
    assert _index(e.run.calls, lambda c: c == ["systemctl", "restart", "wazuh-manager"], "restart") > t


def test_bad_wazuh_check_rolls_the_decoder_back_too(tmp_path):
    from chp_site import wazuh as w
    e = Env(tmp_path)
    dec = e.root / "var/ossec/etc/decoders" / w.DOCS_DECODERS_FILE
    assert not dec.exists()
    _bad_wazuh_check(e)
    with pytest.raises(SiteError, match="Wazuh"):
        e.enable()
    assert not dec.exists()                                       # none before: the new one is removed
    e2 = Env(tmp_path / "two")
    dec2 = e2.root / "var/ossec/etc/decoders" / w.DOCS_DECODERS_FILE
    dec2.parent.mkdir(parents=True, exist_ok=True)
    dec2.write_text("<!-- old -->\n")
    _bad_wazuh_check(e2)
    with pytest.raises(SiteError, match="Wazuh"):
        e2.enable()
    assert dec2.read_text() == "<!-- old -->\n"                  # the previous one is put back

# ---------- status ----------

def test_status_not_enabled(tmp_path):
    r = make_root(tmp_path)
    out = D.status(r, Run(r))
    assert len(out) == 1 and "not enabled" in out[0]


def test_status_reports_services_and_md5_ok(tmp_path):
    e = Env(tmp_path)
    e.enable()
    out = D.status(e.root, e.run)
    assert any(FQDN in x for x in out)
    assert any(x.startswith("httpd: active") for x in out)
    assert not any("DEGRADED" in x for x in out)
    probe = next(c for c in e.run.calls if "MD5" in " ".join(c))
    assert probe[:4] == ["runuser", "-u", "apache", "--"] and "nextcloud" in probe
    assert "SELECT MD5('chp')" in probe


def test_status_degraded_when_database_refuses_md5(tmp_path):
    e = Env(tmp_path)
    e.enable()
    base = e.run.__class__.__call__

    def fips(self, argv, **kw):
        if "MD5" in " ".join(argv):
            return R(1, "", "ERROR:  could not compute MD5 hash: unsupported")
        return base(self, argv, **kw)
    e.run.__class__ = type("Fips", (Run,), {"__call__": fips})
    out = D.status(e.root, e.run)
    assert "DEGRADED: database MD5 unavailable (folder moves/renames/deletes refused)" in out


def test_md5_constant():
    import hashlib
    assert D.MD5_CHP == hashlib.md5(b"chp").hexdigest()


# ---------- review fixes (Task 5 review) ----------

def test_failed_restart_is_redone_by_the_next_run(tmp_path):
    e = Env(tmp_path)
    e.run.fail_restart = "httpd"
    with pytest.raises(SiteError):
        e.enable()
    mark = e.root / D.MARK
    assert "httpd" in mark.read_text()
    conf = (e.root / "etc/chp/documents.conf").read_text()
    assert "ENABLED=no" in conf and "ENABLED=yes" not in conf                 # not proven yet
    assert "ENABLED" in D.status(e.root, e.run)[0]
    e.run.fail_restart = None
    n = len(e.run.calls)
    e.enable()
    assert any(c[:2] == ["systemctl", "restart"] and "httpd" in c for c in e.run.calls[n:])
    assert not mark.exists()
    assert "ENABLED=yes" in (e.root / "etc/chp/documents.conf").read_text()


def test_egress_address_change_restarts_the_egress_unit(tmp_path):
    e = Env(tmp_path)
    e.enable()
    (e.root / "etc/chp/nextcloud-egress-addr.nft").write_text("define CHP_NC_SERVER_IP = 192.168.100.99\n")
    n = len(e.run.calls)
    e.enable()
    again = e.run.calls[n:]
    assert ["systemctl", "restart", "chp-nextcloud-egress.service"] in again
    assert (e.root / "etc/chp/nextcloud-egress-addr.nft").read_text() == "define CHP_NC_SERVER_IP = 192.168.100.30\n"


def test_wazuh_manager_restarted_when_not_active(tmp_path):
    e = Env(tmp_path)
    e.enable()
    e.run.wazuh_active = False
    n = len(e.run.calls)
    e.enable()
    assert ["systemctl", "restart", "wazuh-manager"] in e.run.calls[n:]


def test_stray_group_on_cui_is_removed_and_share_read_back(tmp_path):
    e = Env(tmp_path)
    e.enable()
    cui = next(i for i, f in e.nc.folders.items() if f["name"] == "CUI")
    e.nc.folders[cui]["groups"]["chp-users"] = ["read", "write", "delete", "share"]     # hand-added in the UI
    e.enable()
    assert e.nc.folders[cui]["groups"] == {"cui-users": ["read", "write", "delete"]}
    assert ["groupfolders:group", str(cui), "chp-users", "--delete"] in e.nc.calls


def test_stray_group_that_cannot_be_removed_is_refused_by_name(tmp_path):
    e = Env(tmp_path)
    e.enable()
    cui = next(i for i, f in e.nc.folders.items() if f["name"] == "CUI")
    e.nc.folders[cui]["groups"]["chp-users"] = ["read", "share"]
    e.nc.sticky_groups = True
    with pytest.raises(SiteError, match="CUI.*chp-users"):
        e.enable()


def test_share_on_cui_users_is_refused_when_read_back_shows_it(tmp_path):
    e = Env(tmp_path)
    base = e.nc.__class__.__call__

    def sharing(self, argv, env=None):
        if argv[:1] == ["groupfolders:group"] and argv[2:3] == ["cui-users"]:
            argv = argv + ["share"]                      # a groupfolders that ignores the list we gave it
        return base(self, argv, env)
    e.nc.__class__ = type("Sharing", (NC,), {"__call__": sharing})
    with pytest.raises(SiteError, match="share"):
        e.enable()
    assert not any("share off" in r[0][1].get("step", "") for r in e.records)


def test_oidc_client_without_pkce_is_refused(tmp_path):
    e = Env(tmp_path)
    e.kcli.clients["nextcloud"] = []
    orig = KanidmCli.__call__

    def nopkce(self, argv):
        if argv[:4] == ["system", "oauth2", "get", "nextcloud"]:
            return 0, "name: nextcloud\noauth2_allow_insecure_client_disable_pkce: true\n", ""
        return orig(self, argv)
    e.kcli.__class__ = type("NoPkce", (KanidmCli,), {"__call__": nopkce})
    with pytest.raises(SiteError, match="PKCE"):
        e.enable()


def test_oauth2_get_output_never_in_an_error(tmp_path):
    e = Env(tmp_path)
    orig = KanidmCli.__call__

    def garbage(self, argv):
        if argv[:3] == ["system", "oauth2", "get"]:
            return 0, "oauth2_rs_basic_secret: TOPSECRETVALUE\n", ""
        return orig(self, argv)
    e.kcli.__class__ = type("Garbage", (KanidmCli,), {"__call__": garbage})
    with pytest.raises(SiteError) as ex:
        e.enable()
    assert "TOPSECRETVALUE" not in str(ex.value) and "not shown" in str(ex.value)


def test_pending_secret_is_reused_after_a_failed_run(tmp_path):
    e = Env(tmp_path)
    p = e.pending / "documents" / f"{SRV}-nextcloud-admin.secret"
    p.parent.mkdir(parents=True)
    p.write_text("NEXTCLOUD_ADMIN_USER=ncadmin\nNEXTCLOUD_ADMIN_PASSWORD=" + "k" * 43 + "\n")
    e.enable()
    env = next(env for c, env in zip(e.nc.calls, e.nc.envs) if c[0] == "user:add")
    assert env["OC_PASS"] == "k" * 43
    assert ("k" * 43) in (e.stick / "escrow" / f"{SRV}-nextcloud-admin.secret").read_text()


def test_mail_refusal_comes_before_any_change(tmp_path):
    e = Env(tmp_path, mta=True)
    with pytest.raises(SiteError, match="postfix"):
        e.enable()
    assert all(c[:2] == ["rpm", "-q"] for c in e.run.calls) and e.records == [] and e.kcli.calls == []


def test_bad_zone_never_replaces_the_live_one(tmp_path):
    e = Env(tmp_path)
    live = (e.root / "var/named/iso2.lab.test.zone").read_text()
    base = Run.__call__

    def badzone(self, argv, **kw):
        if argv[:1] == ["named-checkzone"]:
            self.calls.append(list(argv))
            return R(1, "zone iso2.lab.test/IN: bad")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadZone", (Run,), {"__call__": badzone})
    with pytest.raises(SiteError, match="named-checkzone"):
        e.enable()
    assert (e.root / "var/named/iso2.lab.test.zone").read_text() == live
    assert not list((e.root / "var/named").glob("*.chp-new"))
    chk = next(c for c in e.run.calls if c[:1] == ["named-checkzone"])
    assert chk[-1].endswith(".chp-new")


def test_postgresql_must_be_16(tmp_path):
    e = Env(tmp_path)
    e.run.pgver = "13.20"
    with pytest.raises(SiteError, match="16"):
        e.enable()
    assert e.nc.calls == []


def test_module_enable_failure_refuses(tmp_path):
    e = Env(tmp_path)
    base = Run.__call__

    def nomod(self, argv, **kw):
        if "module" in argv:
            import subprocess
            raise subprocess.CalledProcessError(1, argv)
        return base(self, argv, **kw)
    e.run.__class__ = type("NoMod", (Run,), {"__call__": nomod})
    with pytest.raises(SiteError, match="module"):
        e.enable()


def test_fapolicyd_not_restarted_when_nothing_needs_it(tmp_path):
    e = Env(tmp_path)
    e.enable()
    n = len(e.run.calls)
    done = e.enable()
    assert ["systemctl", "restart", "fapolicyd"] not in e.run.calls[n:]
    assert any("no restart needed" in d for d in done)


def test_status_when_off_and_when_unfinished(tmp_path):
    r = make_root(tmp_path)
    run = Run(r)
    assert "not enabled" in D.status(r, run)[0] and run.calls == []
    (r / "etc/chp/documents.conf").write_text("ENABLED=no\nFQDN=x\n")
    assert "has not finished" in D.status(r, run)[0]


# ---------- round 2 ----------

def _upd(calls):
    return [c for c in calls if c[:3] == ["fapolicyd-cli", "--file", "update"]]


def test_config_php_trust_refreshed_after_the_last_write(tmp_path):
    e = Env(tmp_path)
    nc = e.nc
    tl = e.run.calls                                           # one timeline: occ calls go into run's list too

    def occ(argv, env=None):
        tl.append(["OCC", *argv])
        return nc(argv, env)
    D.enable(SRV, dict(SITE), HS, run=e.run, occ=occ, kanidm=e.k, root=e.root, record=lambda *a, **k: None,
             data_is_mount=True, stick=e.stick, pending=e.pending, chown=lambda *a: None, now=lambda: "x", sleep=lambda s: None)
    u = _index(tl, lambda c: c[:3] == ["fapolicyd-cli", "--file", "update"], "trust update")
    assert tl[u + 1] == ["fapolicyd-cli", "--update"]
    assert _index(tl, lambda c: c == ["systemctl", "restart", "fapolicyd"], "restart") > u
    assert not [c for c in tl[u:] if c[:1] == ["OCC"]]         # no occ call (no config.php write) after the update
    # a run that changes config.php (a setting drifted) refreshes the entry and restarts fapolicyd
    e.nc.sysconf[("maintenance",)] = "false"; e.nc._cfg()       # NextCloud wrote a key enable does not manage
    n = len(e.run.calls)
    e.enable()
    assert _upd(e.run.calls[n:]) and ["systemctl", "restart", "fapolicyd"] in e.run.calls[n:]
    # a run that changes nothing does neither
    n = len(e.run.calls)
    e.enable()
    assert not _upd(e.run.calls[n:]) and ["systemctl", "restart", "fapolicyd"] not in e.run.calls[n:]


def test_wazuh_check_failure_keeps_an_earlier_mark(tmp_path):
    e = Env(tmp_path)
    e.enable()
    (e.root / D.MARK).parent.mkdir(parents=True, exist_ok=True)
    (e.root / D.MARK).write_text("wazuh-manager\n")            # an earlier restart failed
    (e.root / "var/ossec/etc/rules/chp_nextcloud_rules.xml").write_text("<group name='older'/>\n")
    base = Run.__call__

    def bad(self, argv, **kw):
        if argv[:1] == ["/var/ossec/bin/wazuh-analysisd"]:
            return R(1, "", "rule error")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadRun", (Run,), {"__call__": bad})
    with pytest.raises(SiteError, match="old rules are back"):
        e.enable()
    assert "wazuh-manager" in (e.root / D.MARK).read_text()


def test_wazuh_check_failure_with_nothing_changed_says_so(tmp_path):
    e = Env(tmp_path)
    e.enable()
    e.run.wazuh_active = False                                  # forces the check without a file change
    base = Run.__call__

    def bad(self, argv, **kw):
        if argv[:1] == ["/var/ossec/bin/wazuh-analysisd"]:
            return R(1, "", "rule error")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadRun", (Run,), {"__call__": bad})
    with pytest.raises(SiteError) as ex:
        e.enable()
    assert "nothing was changed" in str(ex.value) and "old rules are back" not in str(ex.value)


def test_unwritable_marker_is_a_plain_error(tmp_path):
    e = Env(tmp_path)
    blocker = e.root / "var/lib/chp/documents"
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("not a directory")                       # the marker's directory cannot be made
    with pytest.raises(SiteError, match="restart-pending"):
        e.enable()


# ---------- round 3: the trust entry is compared with the file itself ----------

class FailTrustUpdate(Run):
    def __call__(self, argv, **kw):
        if argv[:3] == ["fapolicyd-cli", "--file", "update"]:
            self.calls.append(list(argv))
            import subprocess
            raise subprocess.CalledProcessError(1, argv)
        return super().__call__(argv, **kw)


def test_failed_trust_update_is_retried_on_rerun(tmp_path):
    e = Env(tmp_path)
    e.enable()
    e.nc.sysconf[("maintenance",)] = "false"; e.nc._cfg()       # drift; this run's trust update then fails
    e.run.__class__ = FailTrustUpdate
    with pytest.raises(SiteError):
        e.enable()
    e.run.__class__ = Run
    n = len(e.run.calls)
    e.enable()                                                  # config.php is already at its new content
    assert _upd(e.run.calls[n:]) and ["systemctl", "restart", "fapolicyd"] in e.run.calls[n:]
    assert D._trust_entry(e.root / "etc/fapolicyd/trust.d/nextcloud", D.CONFIG_PHP) == \
        D._size_sha(e.root / "etc/nextcloud/config.php")


def test_runtime_drift_between_runs_is_caught(tmp_path):
    e = Env(tmp_path)
    e.enable()
    e.nc.sysconf[("instanceid",)] = "rotated"; e.nc._cfg()      # NextCloud rewrote config.php at run time
    n = len(e.run.calls)
    e.enable()
    assert _upd(e.run.calls[n:])


def test_unparseable_trust_entry_is_stale(tmp_path):
    e = Env(tmp_path)
    e.enable()
    (e.root / "etc/fapolicyd/trust.d/nextcloud").write_text("/etc/nextcloud/config.php garbage\n")
    n = len(e.run.calls)
    e.enable()
    assert _upd(e.run.calls[n:])


def test_unwritable_pending_secret_is_a_plain_error(tmp_path):
    e = Env(tmp_path)
    e.pending.mkdir()
    (e.pending / "documents").write_text("not a directory")
    with pytest.raises(SiteError, match="break-glass secret file"):
        e.enable()
    assert not [c for c in e.nc.calls if c[0] == "user:add"]


def test_change_then_later_failure_then_rerun_refreshes_trust(tmp_path):
    e = Env(tmp_path)
    e.enable()
    assert len(_upd(e.run.calls)) == 1                          # run 1: add before the install, refresh after it
    e.nc.sysconf[("maintenance",)] = "false"; e.nc._cfg()       # config.php changed between runs...
    (e.root / D.CERT).unlink()
    nc = e.nc

    class FailCert(Run):
        def __call__(self, argv, **kw):
            if argv[:1] == ["/usr/libexec/chp/cert-renew-nextcloud"]:
                nc.sysconf[("instanceid",)] = "rotated"; nc._cfg()   # ...and again during the run, then it fails
                import subprocess
                raise subprocess.CalledProcessError(1, argv)
            return super().__call__(argv, **kw)
    e.run.__class__ = FailCert
    n = len(e.run.calls)
    with pytest.raises(SiteError):
        e.enable()
    assert len(_upd(e.run.calls[n:])) == 1                      # run 2: refreshed before its first occ call only
    assert D._trust_entry(e.root / "etc/fapolicyd/trust.d/nextcloud", D.CONFIG_PHP) != \
        D._size_sha(e.root / "etc/nextcloud/config.php")        # the write during run 2 left the entry stale
    e.run.__class__ = Run
    n = len(e.run.calls)
    e.enable()
    assert len(_upd(e.run.calls[n:])) == 1                      # run 3 refreshes it before its first occ call
    assert D._trust_entry(e.root / "etc/fapolicyd/trust.d/nextcloud", D.CONFIG_PHP) == \
        D._size_sha(e.root / "etc/nextcloud/config.php")


# ---------- round 4: exactly one valid trust entry; remaining OSError paths ----------

SHA_A, SHA_B = "a" * 64, "b" * 64


def test_trust_entry_duplicates_are_stale_in_both_orders(tmp_path):
    t = tmp_path / "nextcloud"
    for text in (f"{D.CONFIG_PHP} 10 {SHA_A}\n{D.CONFIG_PHP} 9 {SHA_B}\n",     # correct, then a stale duplicate
                 f"{D.CONFIG_PHP} 9 {SHA_B}\n{D.CONFIG_PHP} 10 {SHA_A}\n"):    # stale, then correct
        t.write_text(text)
        assert D._trust_entry(t, D.CONFIG_PHP) is None
    t.write_text(f"{D.CONFIG_PHP} 10 {SHA_A}\n")
    assert D._trust_entry(t, D.CONFIG_PHP) == ("10", SHA_A)


def test_trust_entry_ignores_a_bak_path_and_parses_spaces(tmp_path):
    t = tmp_path / "nextcloud"
    t.write_text(f"{D.CONFIG_PHP}.bak 10 {SHA_A}\n")
    assert D._trust_entry(t, D.CONFIG_PHP) is None and D._trust_lines(t, D.CONFIG_PHP) == []
    t.write_text(f"{D.CONFIG_PHP}.bak 10 {SHA_A}\n{D.CONFIG_PHP} 7 {SHA_B}\n")
    assert D._trust_entry(t, D.CONFIG_PHP) == ("7", SHA_B)
    t.write_text(f"/srv/my files/config.php 12 {SHA_A}\n")
    assert D._trust_entry(t, "/srv/my files/config.php") == ("12", SHA_A)
    assert D._trust_entry(t, "/srv/my") is None


def test_trust_entry_size_must_be_canonical(tmp_path):
    t = tmp_path / "nextcloud"
    t.write_text(f"{D.CONFIG_PHP} 010 {SHA_A}\n")
    assert D._trust_entry(t, D.CONFIG_PHP) is None and D._trust_lines(t, D.CONFIG_PHP) == [None]
    t.write_text(f"{D.CONFIG_PHP} 0 {SHA_A}\n")
    assert D._trust_entry(t, D.CONFIG_PHP) == ("0", SHA_A)


@pytest.mark.parametrize("stale_first", [False, True])
def test_duplicate_trust_entry_is_refreshed_on_rerun(tmp_path, stale_first):
    e = Env(tmp_path)
    e.enable()
    t = e.root / "etc/fapolicyd/trust.d/nextcloud"
    good = t.read_text().strip()
    stale = f"{D.CONFIG_PHP} 1 {SHA_B}"
    t.write_text("\n".join([stale, good] if stale_first else [good, stale]) + "\n")
    n = len(e.run.calls)
    e.enable()
    assert len(_upd(e.run.calls[n:])) == 1 and ["systemctl", "restart", "fapolicyd"] in e.run.calls[n:]
    assert D._trust_lines(t, D.CONFIG_PHP) == [D._size_sha(e.root / "etc/nextcloud/config.php")]


def test_bak_entry_does_not_count_as_config_php_added(tmp_path):
    e = Env(tmp_path)
    t = e.root / "etc/fapolicyd/trust.d/nextcloud"
    t.parent.mkdir(parents=True)
    t.write_text(f"{D.CONFIG_PHP}.bak 10 {SHA_A}\n")
    e.enable()
    assert [c for c in e.run.calls if c[:3] == ["fapolicyd-cli", "--file", "add"]]
    assert D._trust_entry(t, D.CONFIG_PHP) == D._size_sha(e.root / "etc/nextcloud/config.php")


def test_unreadable_trust_file_is_a_plain_error(tmp_path):
    e = Env(tmp_path)
    (e.root / "etc/fapolicyd/trust.d/nextcloud").mkdir(parents=True)     # exists, cannot be read as a file
    with pytest.raises(SiteError, match="trust.d/nextcloud"):
        e.enable()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a 0000 file")
def test_unreadable_pending_secret_is_a_plain_error(tmp_path):
    e = Env(tmp_path)
    p = e.pending / "documents" / f"{SRV}-nextcloud-admin.secret"
    p.parent.mkdir(parents=True)
    p.write_text("NEXTCLOUD_ADMIN_PASSWORD=" + "k" * 43 + "\n")
    p.chmod(0)
    try:
        with pytest.raises(SiteError, match="could not read the pending break-glass secret file .*admin.secret"):
            e.enable()
    finally:
        p.chmod(0o600)
    assert not [c for c in e.nc.calls if c[0] == "user:add"]


def test_unreadable_ossec_conf_is_a_plain_error(tmp_path):
    e = Env(tmp_path)
    conf = e.root / "var/ossec/etc/ossec.conf"
    conf.unlink()
    conf.mkdir()                                                # exists, cannot be read as a file
    with pytest.raises(SiteError, match="could not read .*ossec.conf"):
        e.enable()


def test_wazuh_rollback_when_new_rules_cannot_be_removed(tmp_path, monkeypatch):
    e = Env(tmp_path)
    conf = e.root / "var/ossec/etc/ossec.conf"
    old_conf = conf.read_text()
    rules = e.root / "var/ossec/etc/rules/chp_nextcloud_rules.xml"
    assert not rules.exists()                                   # no old rules: the rollback must remove the new ones
    base = Run.__call__

    def bad(self, argv, **kw):
        if argv[:1] == ["/var/ossec/bin/wazuh-analysisd"]:
            return R(1, "", "rule error")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadRun", (Run,), {"__call__": bad})
    real_unlink = Path.unlink

    def unlink(self, *a, **k):
        if self == rules:
            raise PermissionError(13, "Permission denied")
        return real_unlink(self, *a, **k)
    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(SiteError) as ex:
        e.enable()
    msg = str(ex.value)
    assert conf.read_text() == old_conf                         # ossec.conf is restored anyway
    assert "previous" in msg and "ossec.conf is back" in msg
    assert "NOT rolled back" in msg and str(rules) in msg and "Permission denied" in msg
    assert "old rules are back" not in msg
    assert not (e.root / D.MARK).exists() or "wazuh-manager" not in (e.root / D.MARK).read_text()
    assert ["systemctl", "restart", "wazuh-manager"] not in e.run.calls


def _bad_wazuh_check(e):
    base = Run.__call__

    def bad(self, argv, **kw):
        if argv[:1] == ["/var/ossec/bin/wazuh-analysisd"]:
            return R(1, "", "rule error")
        return base(self, argv, **kw)
    e.run.__class__ = type("BadRun", (Run,), {"__call__": bad})


def test_wazuh_rollback_when_old_rules_cannot_be_put_back(tmp_path, monkeypatch):
    # _put(rules, old_rules) failing must not skip restoring ossec.conf or clearing the restart mark
    e = Env(tmp_path)
    conf = e.root / "var/ossec/etc/ossec.conf"
    old_conf = conf.read_text()
    rules = e.root / "var/ossec/etc/rules/chp_nextcloud_rules.xml"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text("<group name='old'/>\n")
    _bad_wazuh_check(e)
    real_put = D._put

    def put(path, text, mode, chown=None):
        if path == rules and text == "<group name='old'/>\n":
            raise SiteError(f"could not write {path} (Read-only file system); fix it, then re-run chp-site documents enable")
        return real_put(path, text, mode, chown)
    monkeypatch.setattr(D, "_put", put)
    with pytest.raises(SiteError) as ex:
        e.enable()
    msg = str(ex.value)
    assert conf.read_text() == old_conf                         # ossec.conf is restored anyway
    dec = e.root / "var/ossec/etc/decoders/chp_docs_decoders.xml"            # Plan 3 Task 9: rolled back too
    assert msg == ("the Wazuh rule check (wazuh-analysisd -t) failed on the new NextCloud rules; "
                   f"the new decoders file {dec} is removed; "
                   f"the previous {conf} is back; NOT rolled back: the previous {rules} could not be restored "
                   f"(could not write {rules} (Read-only file system); fix it, then re-run chp-site documents enable); "
                   "the manager was not restarted; fix that by hand before restarting Wazuh: rule error")
    assert not (e.root / D.MARK).exists() or "wazuh-manager" not in (e.root / D.MARK).read_text()
    assert ["systemctl", "restart", "wazuh-manager"] not in e.run.calls


def test_wazuh_rollback_reports_a_restart_mark_that_cannot_be_cleared(tmp_path, monkeypatch):
    e = Env(tmp_path)
    conf = e.root / "var/ossec/etc/ossec.conf"
    old_conf = conf.read_text()
    _bad_wazuh_check(e)

    real_unmark = D._unmark

    def unmark(root, units):
        if units == ["wazuh-manager"]:
            raise SiteError("could not clear /x/restart-pending (Permission denied)")
        return real_unmark(root, units)
    monkeypatch.setattr(D, "_unmark", unmark)
    with pytest.raises(SiteError) as ex:
        e.enable()
    msg = str(ex.value)
    assert conf.read_text() == old_conf
    assert "is back" in msg and "NOT rolled back: the wazuh-manager restart mark could not be cleared " \
           "(could not clear /x/restart-pending (Permission denied))" in msg
    assert ["systemctl", "restart", "wazuh-manager"] not in e.run.calls


def test_trust_lines_exists_error_is_a_plain_error(tmp_path, monkeypatch):
    tf = tmp_path / "trust.d" / "nextcloud"
    real_exists = Path.exists

    def exists(self, *a, **k):
        if self == tf:
            raise PermissionError(13, "Permission denied")
        return real_exists(self, *a, **k)
    monkeypatch.setattr(Path, "exists", exists)
    with pytest.raises(SiteError, match=r"could not read .*trust\.d/nextcloud \(Permission denied\)"):
        D._trust_lines(tf, D.CONFIG_PHP)


# ---------- nightly tag check and share-link canary (Plan 2 Task 6) ----------
import sqlite3

TOKEN = "canary-app-token-0123456789abcdef"
SCHEMA = """
CREATE TABLE oc_group_folders (folder_id INTEGER, mount_point TEXT, storage_id INTEGER, acl INTEGER);
CREATE TABLE oc_group_folders_acl (acl_id INTEGER, fileid INTEGER, mapping_type TEXT, mapping_id TEXT, mask INTEGER,
                                   permissions INTEGER);
CREATE TABLE oc_group_user (gid TEXT, uid TEXT);
CREATE TABLE oc_user_oidc (id INTEGER, user_id TEXT, display_name TEXT);
CREATE TABLE oc_group_folders_groups (folder_id INTEGER, group_id TEXT, permissions INTEGER, circle_id TEXT);
CREATE TABLE oc_storages (numeric_id INTEGER, id TEXT);
CREATE TABLE oc_mimetypes (id INTEGER, mimetype TEXT);
CREATE TABLE oc_filecache (fileid INTEGER, storage INTEGER, path TEXT, name TEXT, mimetype INTEGER);
CREATE TABLE oc_systemtag (id INTEGER, name TEXT, visibility INTEGER, editable INTEGER);
CREATE TABLE oc_systemtag_object_mapping (objectid TEXT, objecttype TEXT, systemtagid INTEGER);
CREATE TABLE oc_appconfig (appid TEXT, configkey TEXT, configvalue TEXT);
CREATE TABLE oc_share (id INTEGER, share_type INTEGER, file_source INTEGER, uid_owner TEXT, share_with TEXT);
"""
IDS = {"CUI": 1, "FCI": 2, "Archive": 3, "Operations": 4, "Internal": 5, "Public": 6}
CUI_TAG, FCI_TAG = 1, 2
GOOD_APP = {"enabled": "yes", "rules": '{"1":"1","2":"2","3":"1"}', "contain": "[1,2,3]",
            "contain_allow": "[[1,3],[3,1]]"}


class DB:
    """NextCloud's database as the nightly check sees it (sqlite stands in for PostgreSQL; the check's SQL is portable)."""
    def __init__(self, app=None, canary=True):
        self.c = sqlite3.connect(":memory:")
        self.c.row_factory = sqlite3.Row
        self.c.executescript(SCHEMA)
        self.queries = []
        self.next_id = 100
        self.roots = {}
        self.c.executemany("INSERT INTO oc_mimetypes VALUES (?, ?)", [(1, "httpd/unix-directory"), (2, "text/plain")])
        self.c.executemany("INSERT INTO oc_systemtag VALUES (?, ?, 1, 0)", [(CUI_TAG, "CUI"), (FCI_TAG, "FCI")])
        for n, i in IDS.items():
            self.c.execute("INSERT INTO oc_group_folders VALUES (?, ?, ?, 1)", (i, n, 10 + i))
            self.c.execute("INSERT INTO oc_storages VALUES (?, ?)", (10 + i, f"local::/data/nextcloud/data/__groupfolders/{i}/"))
            g, p = ("cui-users", 15) if n in D.CONTROLLED else ("chp-users", 31)
            self.c.execute("INSERT INTO oc_group_folders_groups VALUES (?, ?, ?, NULL)", (i, g, p))
            self.roots[n] = self.file(n, "files", directory=True)
            if n in D.CONTROLLED:          # the reviewer rule as the lab read it back (logs/76): files|31|1
                self.c.execute("INSERT INTO oc_group_folders_acl VALUES (?, ?, 'group', 'doc-reviewers', 31, 1)",
                               (i, self.roots[n]))
        self.c.execute("INSERT INTO oc_storages VALUES (20, 'home::lab01')")
        self.c.executemany("INSERT INTO oc_group_user VALUES (?, ?)", [("admin", "ncadmin"), ("cui-users", "lab01"),
                                                                      ("cui-users", "chp-canary"), ("chp-users", "lab01")])
        self.c.execute("INSERT INTO oc_user_oidc VALUES (1, 'lab01', 'Lab User 1')")
        for k, v in (GOOD_APP if app is None else app).items():
            self.c.execute("INSERT INTO oc_appconfig VALUES ('chp_foldertag', ?, ?)", (k, v))
        self.c.execute("INSERT INTO oc_appconfig VALUES ('core', 'rules', 'x')")
        self.canary_id = self.file("CUI", "files/" + D.CANARY_NAME, [CUI_TAG]) if canary else None

    def file(self, where, path, tags=(), directory=False):
        st = 20 if where == "home" else 10 + IDS[where]
        self.next_id += 1
        self.c.execute("INSERT INTO oc_filecache VALUES (?, ?, ?, ?, ?)",
                       (self.next_id, st, path, path.rsplit("/", 1)[-1], 1 if directory else 2))
        for t in tags:
            self.c.execute("INSERT INTO oc_systemtag_object_mapping VALUES (?, 'files', ?)", (str(self.next_id), t))
        return self.next_id

    def __call__(self, q):
        self.queries.append(q)
        return [dict(r) for r in self.c.execute(q)]


class CanaryOcc:
    """occ for the canary: the canary account, its app tokens and its enabled flag."""
    def __init__(self, exists=True, groups=("cui-users",)):
        self.exists, self.groups, self.enabled = exists, list(groups), False
        self.tokens, self.calls, self.envs = [], [], []

    def __call__(self, argv, env=None):
        argv = list(argv)
        self.calls.append(argv)
        self.envs.append(env)
        c, a = argv[0], argv[1:]
        if c == "user:info":
            if not self.exists:
                return 1, "", "user not found"
            return 0, json.dumps({"user_id": a[0], "enabled": self.enabled, "groups": self.groups}), ""
        if c == "user:add":
            assert env and env.get("OC_PASS") and env["OC_PASS"] not in " ".join(argv)
            self.exists = True
            self.groups = [argv[argv.index("--group") + 1]] if "--group" in argv else []
            return 0, "", ""
        if c == "group:adduser":
            self.groups.append(a[0])
            return 0, "", ""
        if c == "user:enable":
            self.enabled = True
            return 0, "", ""
        if c == "user:disable":
            self.enabled = False
            return 0, "", ""
        if c == "user:auth-tokens:add":
            self.tokens.append({"id": len(self.tokens) + 1, "name": argv[argv.index("--name") + 1]})
            return 0, f"app password:\n{TOKEN}\n", ""
        if c == "user:auth-tokens:list":
            return 0, json.dumps(self.tokens), ""
        if c == "user:auth-tokens:delete":
            self.tokens = [t for t in self.tokens if str(t["id"]) != a[1]]
            return 0, "", ""
        return 0, "", ""


class Api:
    """NextCloud's HTTPS API as the canary uses it: answers per share type (403 = refused, 200 = created)."""
    def __init__(self, public=403, internal=403, raise_on=None, delete_ok=True, file_exists=True):
        self.answer = {"3": public, "0": internal}
        self.raise_on, self.delete_ok, self.file_exists = raise_on, delete_ok, file_exists
        self.calls, self.shares, self.n = [], {}, 76

    def __call__(self, method, path, user, token, form=None, body=None):
        self.calls.append((method, path, user, token, dict(form or {})))
        if self.raise_on and self.raise_on(method, path, form or {}):
            raise OSError("connection reset")
        if method == "PROPFIND":
            return (207 if self.file_exists else 404), b""
        if method == "PUT":
            self.file_exists = True
            return 201, b""
        if method == "POST" and "/shares" in path:
            st = self.answer[form["shareType"]]
            if st == 200:
                self.n += 1
                self.shares[self.n] = form
                return 200, json.dumps({"ocs": {"meta": {"statuscode": 200}, "data": {"id": str(self.n)}}}).encode()
            return st, json.dumps({"ocs": {"meta": {"statuscode": st, "message": "You are not allowed to share"}}}).encode()
        if method == "GET" and "/shares" in path:
            return 200, json.dumps({"ocs": {"meta": {"statuscode": 200},
                                            "data": [{"id": str(i)} for i in sorted(self.shares)]}}).encode()
        if method == "DELETE" and "/shares/" in path:
            if not self.delete_ok:
                return 500, b""
            self.shares.pop(int(path.split("?")[0].rsplit("/", 1)[-1]), None)
            return 200, b""
        return 404, b""


class CheckRun:
    def __init__(self, md5=True):
        self.md5, self.calls = md5, []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        if "MD5" in " ".join(argv):
            return R(0, D.MD5_CHP + "\n") if self.md5 else R(1, "", "ERROR: could not compute MD5 hash")
        return R()


def check_root(tmp_path, enabled="yes", trust=True):
    r = tmp_path / "root"
    (r / "etc/chp").mkdir(parents=True)
    (r / "etc/chp/documents.conf").write_text(D.conf_text(FQDN, "192.168.100.30", 14, {n: str(i) for n, i in IDS.items()},
                                                          enabled))
    cfg = r / "etc/nextcloud/config.php"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("<?php $CONFIG = array('instanceid' => 'x');\n")
    tf = r / "etc/fapolicyd/trust.d/nextcloud"
    tf.parent.mkdir(parents=True)
    size, sha = D._size_sha(cfg)
    tf.write_text(f"{D.CONFIG_PHP} {size} {sha}\n" if trust else f"{D.CONFIG_PHP} 1 {'0' * 64}\n")
    return r


def do_check(tmp_path, db=None, api=None, occ=None, run=None, **kw):
    r = kw.pop("root", None) or check_root(tmp_path, **kw)
    db, api, occ, run = db or DB(), api or Api(), occ or CanaryOcc(), run or CheckRun()
    lines = D.check(r, run, sql=db, api=api, occ=occ, now=lambda: 1_800_000_000, chown=lambda p: None)
    res = json.loads((r / D.CHECK_RESULT).read_text())
    return lines, res, (r, db, api, occ, run)


def keys(res):
    return {a["key"] for a in res["alerts"]}


def test_tag_check_clean_site_is_ok_and_result_written_0600(tmp_path):
    lines, res, (r, *_rest) = do_check(tmp_path)
    assert res["alerts"] == [], res["alerts"]
    assert not any(x.startswith("ALERT") for x in lines)
    p = r / D.CHECK_RESULT
    assert str(D.CHECK_RESULT) == "var/lib/chp/documents/check.json"
    assert (p.stat().st_mode & 0o777) == 0o600 and (p.parent.stat().st_mode & 0o777) == 0o700
    assert res["epoch"] == 1_800_000_000 and res["degraded"] is False
    assert res["canary"] == {"public": "refused", "internal": "refused"}


def test_tag_check_finds_untagged_files_in_cui_and_fci(tmp_path):
    db = DB()
    ok_cui = db.file("CUI", "files/plan.docx", [CUI_TAG])
    bad_cui = db.file("CUI", "files/sub/untagged.docx")
    db.file("CUI", "files/sub", directory=True)                       # folders need no tag
    bad_fci = db.file("FCI", "files/note.md", [CUI_TAG])               # wrong tag is no tag
    db.file("FCI", "files/ok.md", [FCI_TAG])
    bad_arc = db.file("Archive", "files/old.pdf", [FCI_TAG])           # Archive holds CUI: needs the CUI tag
    db.file("Archive", "files/kept.pdf", [CUI_TAG])
    db.file("CUI", "trash/gone.docx")                                  # not under files/: not a live file
    db.file("Operations", "files/ops.txt")                             # open folders need no tag
    _, res, _ = do_check(tmp_path, db=db)
    assert keys(res) == {f"untagged:{bad_cui}", f"untagged:{bad_fci}", f"untagged:{bad_arc}"}, res["alerts"]
    text = " ".join(a["text"] for a in res["alerts"])
    assert "CUI/sub/untagged.docx" in text and "FCI/note.md" in text and "Archive/old.pdf" in text
    assert str(ok_cui) not in keys(res)
    for q in db.queries:                                               # folder ids/tag ids from conf and DB, SQL only
        assert "oc_" in q


def test_tag_check_finds_untagged_cui_prefixed_anywhere(tmp_path):
    db = DB()
    home = db.file("home", "files/CUI_report_v1.docx")
    lower = db.file("Operations", "files/sub/cui_lower.txt")
    fci = db.file("Public", "files/FCI_quote.xlsx", [CUI_TAG])           # FCI_ needs the FCI tag
    db.file("Internal", "files/FCI_tagged.xlsx", [FCI_TAG])            # tagged (but outside: see below)
    db.file("home", "files/CUI_folder", directory=True)
    db.file("home", "files_trashbin/files/CUI_deleted.d123")
    db.file("home", "files/notcui_x.txt")
    _, res, _ = do_check(tmp_path, db=db)
    k = keys(res)
    assert {f"name:{home}", f"name:{lower}", f"name:{fci}"} <= k, res["alerts"]
    assert not any(x.startswith("name:") for x in k - {f"name:{home}", f"name:{lower}", f"name:{fci}"})
    assert any("home of lab01" in a["text"] and "CUI_report_v1.docx" in a["text"] for a in res["alerts"])


def test_tagged_file_outside_the_controlled_folders_alerts(tmp_path):
    db = DB()
    out = db.file("Internal", "files/FCI_tagged.xlsx", [FCI_TAG])
    home = db.file("home", "files/moved.docx", [CUI_TAG])
    _, res, _ = do_check(tmp_path, db=db)
    assert {f"outside:{out}", f"outside:{home}"} <= keys(res)


def test_tag_check_works_without_the_app(tmp_path):
    db = DB(app={**GOOD_APP, "enabled": "no"})
    bad = db.file("CUI", "files/while-off.docx")
    _, res, (_, _, _, occ, _) = do_check(tmp_path, db=db)
    assert "app:enabled" in keys(res) and f"untagged:{bad}" in keys(res)
    for c in occ.calls:                                              # no app command, no app:* use
        assert not c[0].startswith(("chp:", "app:")), c


@pytest.mark.parametrize("app,key", [
    ({k: v for k, v in GOOD_APP.items() if k != "rules"}, "app:rules"),
    ({**GOOD_APP, "rules": ""}, "app:rules"),
    ({**GOOD_APP, "rules": '{"1":"1","2":"2"}'}, "app:rules"),                   # Archive not covered
    ({**GOOD_APP, "rules": '{"1":"1","2":"2","3":"2"}'}, "app:rules"),           # Archive -> FCI tag
    ({**GOOD_APP, "rules": '{"1":"1","2":"2","3":"1","4":"1"}'}, "app:rules"),   # extra rule
    ({**GOOD_APP, "rules": "not json"}, "app:rules"),
    ({k: v for k, v in GOOD_APP.items() if k != "contain"}, "app:contain"),     # silently disables containment
    ({**GOOD_APP, "contain": "[]"}, "app:contain"),
    ({**GOOD_APP, "contain": "[1,2]"}, "app:contain"),
    ({k: v for k, v in GOOD_APP.items() if k != "contain_allow"}, "app:contain_allow"),
    ({**GOOD_APP, "contain_allow": "[[1,3]]"}, "app:contain_allow"),
    ({**GOOD_APP, "contain_allow": "[[1,3],[3,1],[1,4]]"}, "app:contain_allow"),
    ({k: v for k, v in GOOD_APP.items() if k != "enabled"}, "app:enabled"),
])
def test_app_config_must_be_present_and_match_site_policy(tmp_path, app, key):
    _, res, _ = do_check(tmp_path, db=DB(app=app))
    assert key in keys(res), res["alerts"]


def test_app_config_order_and_number_types_do_not_matter(tmp_path):
    app = {**GOOD_APP, "rules": '{"3":1,"1":"1","2":2}', "contain": '["3",1,2]', "contain_allow": "[[3,1],[1,3]]"}
    _, res, _ = do_check(tmp_path, db=DB(app=app))
    assert res["alerts"] == []


def test_team_folder_not_in_the_rules_is_flagged(tmp_path):
    db = DB()
    # a controlled folder renamed in the UI: enable made a new CUI (id 7); the renamed one keeps cui-users
    db.c.execute("INSERT INTO oc_group_folders VALUES (7, 'CUI old', 17, 0)")
    db.c.execute("INSERT INTO oc_group_folders_groups VALUES (7, 'cui-users', 15, NULL)")
    db.c.execute("INSERT INTO oc_group_folders VALUES (8, 'Scratch', 18, 0)")
    _, res, _ = do_check(tmp_path, db=db)
    assert {"folder:7", "folder:8"} <= keys(res)
    t = next(a["text"] for a in res["alerts"] if a["key"] == "folder:7")
    assert "CUI old" in t and "cui-users" in t


def test_ruled_folder_renamed_or_missing_is_flagged(tmp_path):
    db = DB()
    db.c.execute("UPDATE oc_group_folders SET mount_point = 'CUI renamed' WHERE folder_id = 1")
    db.c.execute("DELETE FROM oc_group_folders WHERE folder_id = 2")
    _, res, _ = do_check(tmp_path, db=db)
    assert {"folder:1", "folder:2"} <= keys(res)


def test_controlled_folder_share_bit_or_stray_group_is_flagged(tmp_path):
    db = DB()
    db.c.execute("UPDATE oc_group_folders_groups SET permissions = 31 WHERE folder_id = 1")
    db.c.execute("INSERT INTO oc_group_folders_groups VALUES (3, 'chp-users', 1, NULL)")
    _, res, _ = do_check(tmp_path, db=db)
    assert {"groups:1", "groups:3"} <= keys(res)


def test_tags_must_exist_and_be_restricted(tmp_path):
    db = DB()
    db.c.execute("UPDATE oc_systemtag SET editable = 1 WHERE name = 'FCI'")
    _, res, _ = do_check(tmp_path, db=db)
    assert "tag:FCI" in keys(res)
    db = DB()
    db.c.execute("DELETE FROM oc_systemtag WHERE name = 'CUI'")
    _, res, _ = do_check(tmp_path / "b", db=db)
    assert "tag:CUI" in keys(res)


def test_share_on_a_controlled_file_is_flagged(tmp_path):
    db = DB()
    f = db.file("CUI", "files/plan.docx", [CUI_TAG])
    db.c.execute("INSERT INTO oc_share VALUES (9, 3, ?, 'lab01', NULL)", (f,))
    _, res, _ = do_check(tmp_path, db=db)
    assert "share:9" in keys(res)


def test_config_php_trust_entry_mismatch_alerts(tmp_path):
    _, res, _ = do_check(tmp_path, trust=False)
    assert "trust" in keys(res)


def test_degraded_md5_is_reported_not_alerted(tmp_path):
    lines, res, _ = do_check(tmp_path, run=CheckRun(md5=False))
    assert res["degraded"] is True and res["alerts"] == []
    assert res["md5"] == "DEGRADED: database MD5 unavailable (folder moves/renames/deletes refused)"
    assert any("DEGRADED: database MD5 unavailable" in x and not x.startswith("ALERT") for x in lines)


def test_not_enabled_is_silent(tmp_path):
    r = tmp_path / "root"
    (r / "etc/chp").mkdir(parents=True)
    lines = D.check(r, CheckRun(), sql=DB(), api=Api(), occ=CanaryOcc(), now=lambda: 1)
    assert lines and "not enabled" in lines[0] and not (r / D.CHECK_RESULT).exists()
    r2 = check_root(tmp_path / "b", enabled="no")
    lines = D.check(r2, CheckRun(), sql=DB(), api=Api(), occ=CanaryOcc(), now=lambda: 1)
    assert "not enabled" in lines[0] or "not finished" in lines[0]


def test_canary_public_link_refused(tmp_path):
    lines, res, (r, _, api, occ, _) = do_check(tmp_path)
    posts = [c for c in api.calls if c[0] == "POST"]
    assert [p[4]["shareType"] for p in posts] == ["3", "0"]
    assert posts[0][4]["path"] == "/" + D.CANARY_FILE and posts[0][4].get("password")
    assert posts[1][4]["shareWith"] == D.ADMIN                         # not in cui-users
    assert all(c[2] == D.CANARY_USER and c[3] == TOKEN for c in api.calls)
    assert res["alerts"] == [] and any("canary" in x and x.startswith("OK") for x in lines)
    assert occ.tokens == [] and occ.enabled is False                    # token deleted, account disabled again


@pytest.mark.parametrize("which", ["public", "internal"])
def test_canary_link_created_is_alerted_and_deleted_at_once(tmp_path, which):
    api = Api(**{which: 200})
    _, res, (_, _, api, occ, _) = do_check(tmp_path, api=api)
    assert f"canary:{which}" in keys(res)
    assert api.shares == {}                                            # deleted
    i = [n for n, c in enumerate(api.calls) if c[0] == "POST"][0 if which == "public" else 1]
    assert api.calls[i + 1][0] == "DELETE"                              # at once, before anything else
    assert res["canary"][which].startswith("CREATED")
    assert occ.tokens == [] and occ.enabled is False


def test_canary_link_that_cannot_be_deleted_says_so(tmp_path):
    _, res, _ = do_check(tmp_path, api=Api(public=200, delete_ok=False))
    t = next(a["text"] for a in res["alerts"] if a["key"] == "canary:public")
    assert "could NOT be deleted" in t and "77" in t


def test_canary_never_leaves_a_link_behind_on_an_error(tmp_path):
    # the link is made, then the connection drops before the answer is read back: the sweep finds and deletes it
    class Drop(Api):
        def __call__(self, method, path, user, token, form=None, body=None):
            if method == "POST" and form and form.get("shareType") == "3":
                super().__call__(method, path, user, token, form)
                raise OSError("connection reset")
            return super().__call__(method, path, user, token, form, body)
    api = Drop(public=200)
    _, res, (_, _, api, occ, _) = do_check(tmp_path, api=api)
    assert api.shares == {} and "canary:error" in keys(res)
    assert occ.tokens == [] and occ.enabled is False


def test_canary_inconclusive_answer_alerts(tmp_path):
    for st in (401, 500, 404):
        _, res, _ = do_check(tmp_path / str(st), api=Api(public=st))
        assert "canary:error" in keys(res), st


def test_canary_sets_up_its_account_and_file_without_storing_a_secret(tmp_path):
    occ = CanaryOcc(exists=False)
    api = Api(file_exists=False)
    _, res, (r, _, api, occ, _) = do_check(tmp_path, occ=occ, api=api)
    add = next(c for c in occ.calls if c[0] == "user:add")
    assert "--password-from-env" in add and D.CANARY_USER in add and "cui-users" in add
    assert any(c[0] == "PUT" and c[1].endswith("/CUI/CUI_chp-canary.txt") for c in api.calls)
    assert occ.enabled is False and occ.tokens == []
    for p in r.rglob("*"):
        if p.is_file():
            assert TOKEN not in p.read_text(errors="ignore"), p
    # leftovers of an earlier, killed run are removed first
    occ2 = CanaryOcc()
    occ2.tokens = [{"id": 9, "name": D.CANARY_TOKEN}, {"id": 10, "name": "other"}]
    occ2.enabled = True
    _, res2, _ = do_check(tmp_path / "b", occ=occ2)
    assert occ2.tokens == [] and occ2.enabled is False                 # every token of the account goes
    t = next(a["text"] for a in res2["alerts"] if a["key"] == "canary:leftover")
    assert "ENABLED" in t and "2 app token(s)" in t


def test_canary_account_added_back_to_cui_users(tmp_path):
    occ = CanaryOcc(groups=())
    do_check(tmp_path, occ=occ)
    assert ["group:adduser", "cui-users", D.CANARY_USER] in occ.calls


def test_names_from_nextcloud_are_cleaned(tmp_path):
    db = DB()
    db.file("CUI", "files/evil\x1b[31m\nALERT fake .docx")
    db.c.execute("INSERT INTO oc_group_folders VALUES (9, 'x\x07`y', 19, 0)")
    lines, res, (r, *_x) = do_check(tmp_path, db=db)
    raw = (r / D.CHECK_RESULT).read_text()
    for a in res["alerts"]:
        assert not any(ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch in "  `" for ch in a["text"] + a["key"])
    for x in lines:
        assert "\n" not in x and "\x1b" not in x
    assert "\\u001b" not in raw


def test_sql_errors_alert_and_the_result_is_still_written(tmp_path):
    def broken(q):
        raise SiteError("psql failed: could not connect")
    _, res, _ = do_check(tmp_path, db=broken)
    assert "check:sql" in keys(res)


def test_default_sql_runs_psql_as_apache_and_reads_json(tmp_path):
    seen = []

    def run(argv, **kw):
        seen.append(list(argv))
        return R(0, '[{"a": 1, "b": "x"}]\n')
    q = D.sql_runner(run)
    assert q("SELECT 1 AS a, 'x' AS b") == [{"a": 1, "b": "x"}]
    a = seen[0]
    assert a[:4] == ["runuser", "-u", "apache", "--"] and "nextcloud" in a and "ON_ERROR_STOP=1" in a
    assert "json_agg" in a[-1] and "SELECT 1 AS a, 'x' AS b" in a[-1]
    with pytest.raises(SiteError):
        D.sql_runner(lambda argv, **kw: R(2, "", "ERROR: relation does not exist"))("SELECT 1")


def test_check_exit_code_and_cli(tmp_path, monkeypatch, capsys):
    from chp_site import cli
    monkeypatch.setattr(D, "check", lambda root, run, **kw: ["OK all good", "ALERT bad thing"])
    assert cli.main(["documents", "check"]) == 1
    assert "ALERT bad thing" in capsys.readouterr().out
    monkeypatch.setattr(D, "check", lambda root, run, **kw: ["OK all good"])
    assert cli.main(["documents", "check"]) == 0


def test_tag_check_never_goes_blind_without_the_directory_mimetype(tmp_path):
    db = DB()
    db.c.execute("DELETE FROM oc_mimetypes WHERE mimetype = 'httpd/unix-directory'")
    bad = db.file("CUI", "files/x.docx")
    _, res, _ = do_check(tmp_path, db=db)
    assert f"untagged:{bad}" in keys(res)


# ---------- Task 6 fix round 1 ----------
import signal


def test_sigterm_mid_canary_still_cleans_up_and_handler_is_restored(tmp_path):
    before = signal.getsignal(signal.SIGTERM)

    class Term(Api):
        def __call__(self, method, path, user, token, form=None, body=None):
            if method == "POST" and form and form.get("shareType") == "3":
                os.kill(os.getpid(), signal.SIGTERM)          # systemd stop / TimeoutStartSec
            return super().__call__(method, path, user, token, form, body)
    occ = CanaryOcc()
    r = check_root(tmp_path)
    with pytest.raises(SystemExit):
        D.check(r, CheckRun(), sql=DB(), api=Term(public=200), occ=occ, now=lambda: 1, chown=lambda p: None)
    assert occ.enabled is False and occ.tokens == []
    assert signal.getsignal(signal.SIGTERM) == before


def test_canary_off_disables_and_deletes_tokens(tmp_path):
    r = check_root(tmp_path)
    occ = CanaryOcc()
    occ.enabled, occ.tokens = True, [{"id": 3, "name": "x"}]
    out = D.canary_off(r, occ)
    assert occ.enabled is False and occ.tokens == [] and out[0].startswith("OK")
    assert "no canary account" in D.canary_off(r, CanaryOcc(exists=False))[0]


def test_cli_canary_off(monkeypatch, capsys):
    from chp_site import cli
    monkeypatch.setattr(D, "canary_off", lambda root, occ: ["OK canary-off: done"])
    assert cli.main(["documents", "canary-off"]) == 0 and "canary-off: done" in capsys.readouterr().out


def test_a_running_check_holds_the_lock(tmp_path):
    import fcntl
    r = check_root(tmp_path)
    fd = D._lock(r)
    try:
        out = D.check(r, CheckRun(), sql=DB(), api=Api(), occ=CanaryOcc(), now=lambda: 1, chown=lambda p: None)
        assert "another check is running" in out[0] and not (r / D.CHECK_RESULT).exists()
        assert "check is running" in D.canary_off(r, CanaryOcc())[0]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    _, res, _ = do_check(tmp_path, root=r)
    assert res["alerts"] == []


class WRun(CheckRun):
    def __init__(self, analysisd_rc=0):
        super().__init__()
        self.rc = analysisd_rc

    def __call__(self, argv, **kw):
        if argv[0].endswith("wazuh-analysisd"):
            self.calls.append(list(argv))
            return R(self.rc, "", "" if not self.rc else "ERROR: rule 100608 invalid")
        return super().__call__(argv, **kw)


def test_canary_wazuh_rule_anchored_to_the_canary_file_id(tmp_path):
    db = DB()
    run = WRun()
    _, res, (r, *_x) = do_check(tmp_path, db=db, run=run)
    p = r / D.CANARY_RULES
    assert res["alerts"] == [] and p.read_text() == D.w.canary_rules(db.canary_id)
    assert f"on {db.canary_id} to" in p.read_text()
    assert ["systemctl", "restart", "wazuh-manager"] in run.calls
    run2 = WRun()
    do_check(tmp_path, root=r, db=db, run=run2)                    # unchanged: no restart
    assert ["systemctl", "restart", "wazuh-manager"] not in run2.calls


def test_canary_wazuh_rule_rolled_back_when_the_check_fails(tmp_path):
    run = WRun(analysisd_rc=1)
    _, res, (r, *_x) = do_check(tmp_path, run=run)
    assert "check:wazuh" in keys(res) and not (r / D.CANARY_RULES).exists()
    assert ["systemctl", "restart", "wazuh-manager"] not in run.calls


def test_positive_control_must_find_the_tagged_canary_file(tmp_path):
    _, res, (r, *_x) = do_check(tmp_path, db=DB(canary=False))
    assert "check:control" in keys(res) and not (r / D.CANARY_RULES).exists()
    db = DB(canary=False)
    db.file("CUI", "files/" + D.CANARY_NAME)                       # there, but untagged
    _, res, _ = do_check(tmp_path / "b", db=db)
    assert "check:control" in keys(res)
    db = DB(canary=False)
    db.file("Operations", "files/" + D.CANARY_NAME, [CUI_TAG])     # tagged, wrong storage
    _, res, _ = do_check(tmp_path / "c", db=db)
    assert "check:control" in keys(res)


def test_controlled_folder_without_a_storage_id_alerts(tmp_path):
    db = DB()
    db.c.execute("UPDATE oc_group_folders SET storage_id = NULL WHERE folder_id = 2")
    _, res, _ = do_check(tmp_path, db=db)
    assert "storage:2" in keys(res) and "check:sql" not in keys(res)


def test_per_folder_more_keys_and_true_totals(tmp_path):
    db = DB()
    for i in range(60):
        db.file("CUI", f"files/u{i}.docx")
    for i in range(55):
        db.file("FCI", f"files/f{i}.md")
    _, res, _ = do_check(tmp_path, db=db)
    k = [a["key"] for a in res["alerts"]]
    assert len(k) == len(set(k))                                    # no duplicate keys
    assert "untagged:CUI:more" in k and "untagged:FCI:more" in k
    assert res["counts"]["untagged:CUI"] == 60 and res["counts"]["untagged:FCI"] == 55
    assert len([x for x in k if x.startswith("untagged:") and x.split(":")[1].isdigit()]) == 100
    t = next(a["text"] for a in res["alerts"] if a["key"] == "untagged:CUI:more")
    assert "60 findings" in t


def test_trust_check_alerts_when_either_side_is_missing(tmp_path):
    r = check_root(tmp_path)
    (r / "etc/nextcloud/config.php").unlink()
    (r / "etc/fapolicyd/trust.d/nextcloud").write_text("")
    _, res, _ = do_check(tmp_path, root=r)
    assert "trust" in keys(res)
    r2 = check_root(tmp_path / "b")
    (r2 / "etc/fapolicyd/trust.d/nextcloud").write_text("")
    _, res, _ = do_check(tmp_path / "b", root=r2)
    assert "trust" in keys(res)


def test_token_output_never_in_an_alert(tmp_path):
    class Leaky(CanaryOcc):
        def __call__(self, argv, env=None):
            if argv[0] == "user:auth-tokens:add":
                self.calls.append(list(argv))
                return 1, f"app password:\n{TOKEN}\n", f"error after {TOKEN}"
            return super().__call__(argv, env)
    _, res, (r, *_x) = do_check(tmp_path, occ=Leaky())
    assert "canary:error" in keys(res)
    assert TOKEN not in (r / D.CHECK_RESULT).read_text()


def test_duplicate_tag_names_alert(tmp_path):
    db = DB()
    db.c.execute("INSERT INTO oc_systemtag VALUES (9, 'CUI', 1, 0)")
    _, res, _ = do_check(tmp_path, db=db)
    assert "tag:CUI:duplicate" in keys(res)


# ---------- Task 6 fix round 2 ----------

class BrokenOcc(CanaryOcc):
    def __call__(self, argv, env=None):
        if argv[0] == "user:info":
            self.calls.append(list(argv))
            return 1, "", "Nextcloud is in maintenance mode, no apps are loaded."
        return super().__call__(argv, env)


def test_canary_off_fails_loudly_when_occ_is_broken(tmp_path):
    r = check_root(tmp_path)
    occ = BrokenOcc()
    occ.enabled, occ.tokens = True, [{"id": 3, "name": "x"}]
    with pytest.raises(SiteError, match="maintenance mode"):
        D.canary_off(r, occ)
    assert "no canary account" in D.canary_off(r, CanaryOcc(exists=False))[0]   # only "user not found" is absent


def test_check_never_tries_to_make_the_account_when_occ_is_broken(tmp_path):
    occ = BrokenOcc()
    _, res, _ = do_check(tmp_path, occ=occ)
    assert "canary:error" in keys(res) and not any(c[0] == "user:add" for c in occ.calls)


# ---------- Task 9c: lab round 2 defects (D3 config.php trust, D4 always-enabled apps, D5 Kanidm group get) ----------

def test_d3_config_php_and_its_trust_entry_exist_before_the_first_occ_call(tmp_path):
    e = Env(tmp_path)
    nc, tl, owners = e.nc, e.run.calls, []

    def occ(argv, env=None):
        tl.append(["OCC", *argv])
        return nc(argv, env)
    D.enable(SRV, dict(SITE), HS, run=e.run, occ=occ, kanidm=e.k, root=e.root, record=lambda *a, **k: None,
             data_is_mount=True, stick=e.stick, pending=e.pending, chown=lambda p: owners.append(p.name),
             now=lambda: "x", sleep=lambda s: None)
    first = _index(tl, lambda c: c[:1] == ["OCC"], "first occ call")
    assert tl[first] == ["OCC", "status", "--output=json"]
    add = _index(tl, lambda c: c[:3] == ["fapolicyd-cli", "--file", "add"], "trust add")
    assert tl[add] == ["fapolicyd-cli", "--file", "add", D.CONFIG_PHP, "--trust-file", "nextcloud"]
    assert tl[add + 1] == ["fapolicyd-cli", "--update"]
    rc = _index(tl, lambda c: c == ["restorecon", D.CONFIG_PHP], "restorecon config.php")
    assert rc < add < first < _index(tl, lambda c: c[:2] == ["OCC", "maintenance:install"], "install")
    assert "config.php.chp-tmp" in owners                      # written as apache:apache (0640), then put in place
    assert len([c for c in tl if c[:3] == ["fapolicyd-cli", "--file", "add"]]) == 1
    cfg = e.root / "etc/nextcloud/config.php"
    assert D._trust_entry(e.root / "etc/fapolicyd/trust.d/nextcloud", D.CONFIG_PHP) == D._size_sha(cfg)
    assert ["systemctl", "restart", "fapolicyd"] in tl


def test_d3_minimal_config_is_valid_php_with_an_empty_config_array():
    assert D.MIN_CONFIG == "<?php\n$CONFIG = array (\n);\n"


def test_d3_the_fake_denies_an_untrusted_config_php_like_fapolicyd(tmp_path):
    e = Env(tmp_path)                                           # the regression the fix is for (lab round 2)
    cfg = e.root / "etc/nextcloud/config.php"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(D.MIN_CONFIG)
    assert e.nc(["status", "--output=json"])[0] == 1
    assert e.nc(["maintenance:install"])[0] == 1 and not e.nc.installed


@pytest.mark.parametrize("left", ["none", "stale"])
def test_d3_rerun_after_a_failed_install_recovers(tmp_path, left):
    """Round 2: the install wrote a partial config.php, fapolicyd denied reading it back, every occ call then failed.
    A re-run refreshes the trust entry before its first occ call and completes."""
    e = Env(tmp_path)
    cfg = e.root / "etc/nextcloud/config.php"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("<?php\n$CONFIG = array (\n  'datadirectory' => '/data/nextcloud/data',\n  'dbtype' => 'pgsql',\n);\n")
    t = e.root / "etc/fapolicyd/trust.d/nextcloud"
    t.parent.mkdir(parents=True)
    t.write_text(f"{D.CONFIG_PHP} 1 {'b' * 64}\n" if left == "stale" else "")
    if left == "none":
        assert e.nc(["status", "--output=json"])[0] == 1        # the state the lab was left in
    done = e.enable()
    assert any("ENABLED=yes" in d for d in done) and e.nc.installed
    pre = _index(e.run.calls, lambda c: c[:2] == ["fapolicyd-cli", "--file"], "first trust call")
    assert e.run.calls[pre][2] == ("add" if left == "none" else "update")
    assert D._trust_entry(t, D.CONFIG_PHP) == D._size_sha(cfg)


def test_d3_existing_config_php_is_never_overwritten(tmp_path):
    e = Env(tmp_path)
    cfg = e.root / "etc/nextcloud/config.php"
    cfg.parent.mkdir(parents=True)
    orig = "<?php\n$CONFIG = array ('instanceid' => 'keep');\n"
    cfg.write_text(orig)
    seen = []

    def occ(argv, env=None):
        seen.append(cfg.read_text())
        return e.nc(argv, env)
    D.enable(SRV, dict(SITE), HS, run=e.run, occ=occ, kanidm=e.k, root=e.root, record=lambda *a, **k: None,
             data_is_mount=True, stick=e.stick, pending=e.pending, chown=lambda *a: None, now=lambda: "x", sleep=lambda s: None)
    assert seen[0] == orig                                      # what NextCloud (or a failed install) left is kept
    assert ["restorecon", D.CONFIG_PHP] not in e.run.calls


def test_d4_apps_off_never_holds_an_always_enabled_app():
    assert not set(D.APPS_OFF) & set(D.ALWAYS_ENABLED)
    assert "appstore" in D.ALWAYS_ENABLED and "appstore" not in D.APPS_OFF
    # NextCloud 35.0.3 core/shipped.json alwaysEnabled (read from the installed nextcloud-chp 35.0.3-4 tree)
    assert set(D.ALWAYS_ENABLED) == {"appstore", "cloud_federation_api", "dav", "federatedfilesharing", "files",
                                     "lookup_server_connector", "oauth2", "profile", "provisioning_api", "settings",
                                     "sharing", "theming", "twofactor_backupcodes", "viewer", "workflowengine"}


def test_d4_enable_passes_with_the_app_store_app_enabled_and_keeps_it_off_by_config(tmp_path):
    e = Env(tmp_path)
    assert "appstore" in e.nc.enabled and "office" in e.nc.enabled
    e.enable()
    assert not [c for c in e.nc.calls if c[:1] == ["app:disable"] and c[1] in D.ALWAYS_ENABLED]
    assert "appstore" in e.nc.enabled                            # cannot be disabled; the store is off by config
    assert e.nc.sysconf[("appstoreenabled",)] == "false"
    assert "office" not in e.nc.enabled                          # the spike disabled it (editors' landing app)


def test_d5_kanidm_group_get_missing_is_none_not_an_error(tmp_path):
    e = Env(tmp_path)
    assert e.k.group("cui-users") is None                       # Kanidm 1.11.2: "No matching group 'cui-users'"
    e.enable()
    assert [c[:3] for c in e.kcli.calls if c[:2] == ["group", "create"]] == [["group", "create", "cui-users"],
                                                                            ["group", "create", "doc-reviewers"]]


# ---- Task 9d: D6 (fapolicyd can die ~1 s after enable's restart), the AIDE note, D10 (documents trust) ----
def _fapo_restarts(calls):
    return [i for i, c in enumerate(calls) if c == ["systemctl", "restart", "fapolicyd"]]


def test_d6_restart_is_verified_by_several_samples_and_fsmark_verify(tmp_path):
    e = Env(tmp_path)
    done = e.enable()
    r = _fapo_restarts(e.run.calls)
    assert len(r) == 1
    after = e.run.calls[r[0]:]
    assert [c for c in after if c == ["systemctl", "is-active", "fapolicyd"]] == [["systemctl", "is-active", "fapolicyd"]] * 3
    assert sum(e.sleeps) >= 5                                             # ~5 s: the crash comes ~1 s after start
    v = _index(after, lambda c: c == ["/usr/libexec/chp/fapolicyd-fsmark", "--verify"], "fsmark --verify")
    assert v > _index(after, lambda c: c[:2] == ["fapolicyd-cli", "--check-status"], "status")
    assert any("Denied accesses: 0" in d for d in done) and not any("unknown" in d for d in done)


def test_d6_daemon_dead_after_restart_is_restarted_once_more(tmp_path):
    e = Env(tmp_path)
    e.run.fapo_dies = {1}
    done = e.enable()
    assert len(_fapo_restarts(e.run.calls)) == 2
    assert any("restarted again" in d and "Denied accesses: 0" in d for d in done)
    assert "fapolicyd" not in D._restart_marks(e.root)
    assert D._kv(e.root / "etc/chp/documents.conf")["ENABLED"] == "yes"


def test_d6_daemon_dead_twice_fails_loudly_and_keeps_the_mark(tmp_path):
    e = Env(tmp_path)
    e.run.fapo_dies = {1, 2}
    with pytest.raises(SiteError) as x:
        e.enable()
    m = str(x.value)
    assert "fapolicyd is NOT running" in m and "check 80" in m and "POA&M" in m and "recvmesg" in m
    assert "unknown" not in m
    assert len(_fapo_restarts(e.run.calls)) == 2
    assert "fapolicyd" in D._restart_marks(e.root)                       # the next run restarts it again
    assert D._kv(e.root / "etc/chp/documents.conf").get("ENABLED") != "yes"
    e.run.fapo_dies = set()
    e.enable()                                                            # a re-run recovers
    assert "fapolicyd" not in D._restart_marks(e.root)


def test_d6_no_denied_counter_is_never_success(tmp_path):
    e = Env(tmp_path)
    e.run.no_counter = True
    with pytest.raises(SiteError) as x:
        e.enable()
    assert "Denied accesses" in str(x.value) and "fapolicyd is NOT running" not in str(x.value)
    assert D._kv(e.root / "etc/chp/documents.conf").get("ENABLED") != "yes"


def test_d6_fsmark_verify_failure_fails_the_run(tmp_path):
    e = Env(tmp_path)
    e.run.fsmark_rc = 1
    with pytest.raises(SiteError) as x:
        e.enable()
    assert "fapolicyd-fsmark --verify" in str(x.value) and "NOT active" in str(x.value)
    assert D._kv(e.root / "etc/chp/documents.conf").get("ENABLED") != "yes"


def test_d6_systemctl_restart_failure_is_retried_once(tmp_path):
    e = Env(tmp_path)
    e.run.fail_restart = "fapolicyd"
    with pytest.raises(SiteError) as x:
        e.enable()
    assert "fapolicyd is NOT running" in str(x.value)
    assert len(_fapo_restarts(e.run.calls)) == 2


def test_aide_note_only_when_this_run_changed_something(tmp_path):
    e = Env(tmp_path)
    e.enable()
    e.records.clear()
    done = e.enable()                                                     # nothing changed
    assert not any("aide-accept" in d for d in done)
    assert any(a[1].get("aide_refresh") == "none" for a, _ in e.records)
    (e.root / "etc/hosts").write_text("127.0.0.1 localhost\n")            # drift: enable puts /etc/hosts back
    done = e.enable()
    assert any("aide-accept" in d and "/etc/hosts" in d for d in done)


def test_d10_documents_trust_refreshes_a_stale_entry_and_verifies(tmp_path):
    e = Env(tmp_path)
    e.enable()
    cfg = e.root / "etc/nextcloud/config.php"
    cfg.write_text(cfg.read_text() + "  'data-fingerprint' => 'x',\n")    # what restore's data-fingerprint does
    tf = e.root / "etc/fapolicyd/trust.d/nextcloud"
    assert D._trust_entry(tf, D.CONFIG_PHP) != D._size_sha(cfg)
    n = len(e.run.calls)
    out = D.trust(e.root, e.run)
    assert D._trust_entry(tf, D.CONFIG_PHP) == D._size_sha(cfg)
    assert out[0].startswith("OK") and "refreshed" in out[0]
    assert e.run.calls[n:] == [["fapolicyd-cli", "--file", "update", D.CONFIG_PHP, "--trust-file", "nextcloud"],
                               ["fapolicyd-cli", "--update"]]               # no restart, nothing marked
    assert "fapolicyd" not in D._restart_marks(e.root)
    assert D.trust(e.root, e.run)[0].startswith("OK") and len(e.run.calls) == n + 2      # already equal: no call


def test_d10_documents_trust_fails_when_the_entry_still_differs(tmp_path):
    e = Env(tmp_path)
    e.enable()
    cfg = e.root / "etc/nextcloud/config.php"
    cfg.write_text("changed\n")

    class NoUpdate(Run):
        def __call__(self, argv, **kw):
            if argv[:2] == ["fapolicyd-cli", "--file"]:
                self.calls.append(list(argv))
                return R()                                                # "succeeds" but writes nothing
            return super().__call__(argv, **kw)
    with pytest.raises(SiteError) as x:
        D.trust(e.root, NoUpdate(e.root))
    assert "still does not match" in str(x.value)


def test_d10_documents_trust_when_not_enabled(tmp_path):
    r = make_root(tmp_path)
    assert D.trust(r, Run(r))[0].startswith("OK documents: not enabled")


def test_cli_documents_trust(monkeypatch, capsys):
    from chp_site import cli
    monkeypatch.setattr(D, "trust", lambda root, run: ["OK fapolicyd trust entry for x refreshed"])
    assert cli.main(["documents", "trust"]) == 0 and "trust entry for x refreshed" in capsys.readouterr().out


# ---------- Plan 3 Task 1: the Plan 2 carries (D13, O8, I2, final-review M3, Task 9d review minors) ----------

def test_enable_turns_on_check_timer(tmp_path):
    """D13 (round 4): enable never enabled chp-documents-check.timer, so the nightly tag check and canary never ran."""
    e = Env(tmp_path)
    done = e.enable()
    assert "chp-documents-check.timer" in D.UNITS
    on = [c for c in e.run.calls if c[:3] == ["systemctl", "enable", "--now"]]
    assert any("chp-documents-check.timer" in c for c in on)
    assert "chp-documents-check.timer" in e.run.enabled_units
    assert any(d.startswith("started:") and "chp-documents-check.timer" in d for d in done)


def test_stray_group_acl_removed(tmp_path):
    """O8 (round 4): a stray group removed from a controlled folder must not leave its ACL rules behind."""
    e = Env(tmp_path)
    e.enable()
    cui = next(i for i, f in e.nc.folders.items() if f["name"] == "CUI")
    e.nc.folders[cui]["groups"]["chp-users"] = ["read", "write", "delete", "share"]     # hand-added in the UI
    e.nc.folders[cui]["rules"].append(["--group", "chp-users", "--", "/", "-delete"])     # and an ACL rule for it
    e.enable()
    clear = ["groupfolders:permissions", str(cui), "--group", "chp-users", "--", "/", "clear"]
    assert clear in e.nc.calls
    assert _index(e.nc.calls, lambda c: c == clear, "clear") > \
        _index(e.nc.calls, lambda c: c == ["groupfolders:group", str(cui), "chp-users", "--delete"], "delete")
    assert not any("chp-users" in r for r in e.nc.folders[cui]["rules"])
    assert any("doc-reviewers" in r for r in e.nc.folders[cui]["rules"])                 # the reviewer rule stays


def test_unit_enabled_by_this_run_is_in_the_aide_note(tmp_path):
    """9d minor 7: re-enabling a unit someone disabled changes /etc/systemd/system (AIDE sees it): say so."""
    e = Env(tmp_path)
    e.enable()
    e.run.enabled_units.discard("chp-documents-check.timer")
    e.records.clear()
    done = e.enable()
    assert any("aide-accept" in d and "unit enabled: chp-documents-check.timer" in d for d in done)
    done = e.enable()
    assert not any("aide-accept" in d for d in done)


def test_fapolicyd_found_dead_is_restarted_even_when_no_restart_is_needed(tmp_path):
    """9d minor 1: the "no restart needed" branch must not report a clean run while fapolicyd is down."""
    e = Env(tmp_path)
    e.enable()
    e.run.fapo_dies = {e.run.fapo_restarts}                            # dead now (died outside enable)
    n = len(e.run.calls)
    done = e.enable()
    assert ["systemctl", "restart", "fapolicyd"] in e.run.calls[n:]
    assert any("was not running" in d and "Denied accesses: 0" in d for d in done)
    assert not any("no restart needed" in d for d in done)


def test_fsmark_verify_warning_is_kept_in_the_step_and_the_record(tmp_path):
    """9d minor 2: fsmark --verify restarted a dead fapolicyd itself (exit 0 + a warning): keep that warning."""
    e = Env(tmp_path)
    e.run.fsmark_warn = ("chp-fapolicyd-fsmark: fapolicyd was NOT active after a restart (allow_filesystem_mark is "
                         "not ours); restarted again: fapolicyd active")
    done = e.enable()
    assert any(d.startswith("fapolicyd restarted") and "restarted again: fapolicyd active" in d for d in done)
    rec = next(a[1] for a, _ in e.records if a[1].get("step") == "fapolicyd")
    assert "restarted again" in rec.get("verify", "")


def test_fsmark_verify_failure_names_how_to_clear_the_record(tmp_path):
    """9d minor 3: after recovery check 80 alerts until the helper is re-run with FSMARK=0: the error says so."""
    e = Env(tmp_path)
    e.run.fsmark_rc = 1
    with pytest.raises(SiteError) as x:
        e.enable()
    assert "FSMARK=0" in str(x.value) and "/usr/libexec/chp/fapolicyd-fsmark" in str(x.value)


def test_trust_refuses_a_rendered_nextcloud_without_documents_conf(tmp_path):
    """9d minor 6: restore must not pass silently on "not enabled" when NextCloud's config.php is there."""
    r = make_root(tmp_path)
    (r / "etc/nextcloud").mkdir(parents=True)
    (r / "etc/nextcloud/config.php").write_text(D.MIN_CONFIG)
    with pytest.raises(SiteError, match="documents.conf"):
        D.trust(r, Run(r))


def test_md5_psql_failure_is_not_reported_as_the_known_degraded_state(tmp_path):
    """M3: PostgreSQL down or peer auth broken is "cannot tell", not the accepted DEGRADED state; the check alerts."""
    def run(argv, **kw):
        if "MD5" in " ".join(argv):
            return R(2, "", "psql: error: connection to server on socket \"/run/postgresql/.s.PGSQL.5432\" failed")
        return R()
    s = D.md5_state(run)
    assert not s.startswith("DEGRADED") and "psql failed" in s and "connection to server" in s
    fips = D.md5_state(lambda a, **k: R(1, "", "ERROR:  could not compute MD5 hash: unsupported"))
    assert fips.startswith("DEGRADED")                                  # the known FIPS state (lab text)
    assert D.md5_state(lambda a, **k: R(0, "0" * 32 + "\n")).startswith("DEGRADED")      # a wrong MD5()
    _, res, _ = do_check(tmp_path, run=lambda a, **k: run(a, **k))
    assert res["degraded"] is False and "check:md5" in keys(res)


def test_check_flags_local_cui_member(tmp_path):
    """I2: cui-users may hold only Kanidm (user_oidc) users and the canary; anything else got in outside Kanidm."""
    db = DB()
    db.c.execute("INSERT INTO oc_group_user VALUES ('cui-users', 'mallory')")             # a local account
    _, res, _ = do_check(tmp_path, db=db)
    assert keys(res) == {"cui-member:mallory"}, res["alerts"]
    t = res["alerts"][0]["text"]
    assert "mallory" in t and "Kanidm" in t
    _, res, _ = do_check(tmp_path / "b")                                  # lab01 (OIDC) + chp-canary: clean
    assert res["alerts"] == []


def test_check_flags_extra_admin(tmp_path):
    """I2: the NextCloud admin group is exactly the break-glass account."""
    db = DB()
    db.c.execute("INSERT INTO oc_group_user VALUES ('admin', 'lab01')")
    _, res, _ = do_check(tmp_path, db=db)
    assert keys(res) == {"admin"} and "lab01" in res["alerts"][0]["text"]
    db = DB()
    db.c.execute("DELETE FROM oc_group_user WHERE gid = 'admin'")
    _, res, _ = do_check(tmp_path / "b", db=db)
    assert keys(res) == {"admin"}


def test_check_flags_missing_reviewer_acl(tmp_path):
    """I2 / owner decision 7: the doc-reviewers read-only rule and advanced permissions on CUI, FCI and Archive; any
    other ACL rule there (O8's orphan, or a rule that widens a reviewer) is flagged too."""
    db = DB()
    db.c.execute("DELETE FROM oc_group_folders_acl WHERE fileid = ?", (db.roots["FCI"],))
    db.c.execute("UPDATE oc_group_folders SET acl = 0 WHERE folder_id = 3")
    db.c.execute("INSERT INTO oc_group_folders_acl VALUES (90, ?, 'group', 'chp-users', 8, 0)", (db.roots["CUI"],))
    _, res, _ = do_check(tmp_path, db=db)
    assert keys(res) == {"acl:2", "advperm:3", "acl-other:1"}, res["alerts"]
    db = DB()
    db.c.execute("UPDATE oc_group_folders_acl SET permissions = 3 WHERE fileid = ?", (db.roots["CUI"],))  # +write
    _, res, _ = do_check(tmp_path / "b", db=db)
    assert keys(res) == {"acl:1"}
    db = DB()
    db.c.execute("UPDATE oc_group_folders SET acl = 0 WHERE folder_id = 4")              # open folders: not checked
    _, res, _ = do_check(tmp_path / "c", db=db)
    assert res["alerts"] == []
