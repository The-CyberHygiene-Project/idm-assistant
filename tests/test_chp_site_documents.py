"""chp-site documents enable|status (ISO 0.7.0 Plan 2 Task 5): every command goes through injected fakes (run, occ, a
Kanidm with a fake CLI); nothing here touches a real system."""
import json
import os
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
            return R(0, "Allowed accesses: 100\nDenied accesses: 0\n")
        if argv[:2] == ["systemctl", "is-active"]:
            if argv[-1] == "wazuh-manager" and not self.wazuh_active:
                return R(3, "inactive\n")
            return R(0, "active\n")
        if argv[:2] == ["systemctl", "restart"] and self.fail_restart and self.fail_restart in argv:
            if kw.get("check"):
                import subprocess
                raise subprocess.CalledProcessError(1, argv)
            return R(1)
        return R()


DEFAULT_APPS = {"files", "dav", "viewer", "files_pdfviewer", "text", "firstrunwizard", "recommendations", "dashboard",
                "photos", "federatedfilesharing", "updatenotification", "weather_status", "systemtags", "workflowengine"}


class NC:
    """A NextCloud as occ sees it."""
    def __init__(self):
        self.installed, self.sysconf, self.appconf = False, {}, {}
        self.enabled = set(DEFAULT_APPS)
        self.users, self.groups, self.folders, self.tags = set(), {"admin"}, {}, {}
        self.providers, self.certs, self.calls, self.envs = set(), set(), [], []
        self.sticky_groups = False
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
        if c == "status":
            return 0, json.dumps({"installed": self.installed}), ""
        if c == "maintenance:install":
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
            self.providers.add(a[0])
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

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        a = argv[:-2]                                  # drop -D idm_admin
        if a[:2] == ["group", "get"]:
            return (0, f"name: {a[2]}\n", "") if a[2] in self.groups else (0, "No matching entries\n", "")
        if a[:2] == ["group", "create"]:
            self.groups.add(a[2])
            return 0, "", ""
        if a[:3] == ["system", "oauth2", "get"]:
            if a[3] not in self.clients:
                return 0, "No matching entries\n", ""
            return 0, f"name: {a[3]}\ndisplayname: NextCloud\n", ""
        if a[:3] == ["system", "oauth2", "create"]:
            self.clients[a[3]] = a[4:]
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
        self.k = Kanidm("idm_admin", run=self.kcli)
        self.records = []
        self.stick = tmp_path / "stick"
        self.stick.mkdir()
        self.pending = tmp_path / "pending"

    def enable(self, host=SRV, site=None, data_is_mount=True, stick="default"):
        return D.enable(host, dict(site or SITE), HS, run=self.run, occ=self.nc, kanidm=self.k, root=self.root,
                        record=lambda *a, **k: self.records.append((a, k)), data_is_mount=data_is_mount,
                        stick=self.stick if stick == "default" else stick, pending=self.pending,
                        chown=lambda *a: None, now=lambda: "20261113T120000Z")


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
             stick=e2.stick, pending=e2.pending, chown=lambda *a: None, now=lambda: "20261113T120000Z")
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
    for n in ("CUI", "FCI", "Archive"):
        assert by[n]["rules"] == [["--group", "doc-reviewers", "--", "/", "+read", "-write", "-create", "-delete",
                                   "-share"]]
    for n in ("Operations", "Internal", "Public"):
        assert by[n]["rules"] == []
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
    add = [(c, env) for c, env in zip(e.nc.calls, e.nc.envs) if c[0] == "user:add"]
    assert len(add) == 1
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
             data_is_mount=True, stick=e.stick, pending=e.pending, chown=lambda *a: None, now=lambda: "x")
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
    e.nc.sysconf[("maintenance",)] = "false"; e.nc._cfg()       # config.php changed...
    (e.root / D.CERT).unlink()                                  # ...and this run fails before the trust step

    class FailCert(Run):
        def __call__(self, argv, **kw):
            if argv[:1] == ["/usr/libexec/chp/cert-renew-nextcloud"]:
                import subprocess
                raise subprocess.CalledProcessError(1, argv)
            return super().__call__(argv, **kw)
    e.run.__class__ = FailCert
    with pytest.raises(SiteError):
        e.enable()
    assert not _upd(e.run.calls)[1:]                             # only the first run's update so far
    e.run.__class__ = Run
    n = len(e.run.calls)
    e.enable()
    assert _upd(e.run.calls[n:])
