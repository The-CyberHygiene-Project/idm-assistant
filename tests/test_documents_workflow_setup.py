"""chp-site documents enable: the server side of the controlled-document workflow (ISO 0.7.0 Plan 3 Task 2). The
Kanidm public client chp-doc, the Bearer-only user_oidc provider, the read-only Compliance and Superseded areas, the
login rewrite and the optional DOC_*/CUI_* site keys. Every command goes through the fakes of
test_chp_site_documents (nothing touches a real system)."""
import re
from pathlib import Path

import pytest

from chp_site import documents as D
from chp_site.sitefile import SiteError, parse_site
from chp_site.sitevars import values
from tests.test_chp_site_documents import DB, FQDN, HS, IDS, Env, do_check, keys
from tests.test_chp_site_sitefile import GOOD

REPO = Path(__file__).resolve().parents[1]
RPM = REPO / "appliance" / "rpm" / "chp-documents"
DOCSITE = GOOD + "SECURITY_ADDONS=yes\nDOCUMENTS=yes\n"
RO = ["+read", "-write", "-create", "-delete", "-share"]


def conf(e):
    return dict(ln.split("=", 1) for ln in (e.root / "etc/chp/documents.conf").read_text().splitlines()
                if "=" in ln and not ln.startswith("#"))


def kc(e, since=0):
    return [c[:-2] for c in e.kcli.calls[since:]]


def fid(e, name):
    return next(i for i, f in e.nc.folders.items() if f["name"] == name)


# ---------- the Kanidm public client chp-doc ----------

def test_doc_client_created_idempotent(tmp_path):
    e = Env(tmp_path)
    e.enable()
    k = kc(e)
    origin = f"https://{FQDN}:8443"
    assert ["system", "oauth2", "create-public", "chp-doc", "CHP doc commands", origin] in k
    assert "chp-doc" in e.kcli.public                                   # public: PKCE S256 always, no secret
    assert ["system", "oauth2", "enable-localhost-redirects", "chp-doc"] in k      # any loopback port (spike logs/49)
    assert ["system", "oauth2", "add-redirect-url", "chp-doc", "http://127.0.0.1/"] in k
    assert ["system", "oauth2", "update-scope-map", "chp-doc", "chp_users", "openid", "profile", "groups"] in k
    assert ["system", "oauth2", "set-refresh-token-expiry", "chp-doc", "28800"] in k             # 8 h
    assert ["system", "oauth2", "prefer-short-username", "chp-doc"] in k
    for g, v in (("cui-users", "cui-users"), ("doc-reviewers", "doc-reviewers"), ("chp_users", "chp-users")):
        assert ["system", "oauth2", "update-claim-map", "chp-doc", "chp_groups", g, v] in k
    assert not [c for c in k if c[:3] == ["system", "oauth2", "show-basic-secret"] and c[3] == "chp-doc"]
    attrs = e.kcli.attrs["chp-doc"]
    assert attrs["oauth2_allow_localhost_redirect"] == ["true"] and attrs["oauth2_refresh_token_expiry"] == ["28800"]
    state = (set(e.kcli.clients), set(e.kcli.public), {n: dict(a) for n, a in e.kcli.attrs.items()})
    n = len(e.kcli.calls)
    done = e.enable()
    assert not [c for c in kc(e, n) if c[2:3] and c[2].startswith("create")]                 # nothing made again
    assert (set(e.kcli.clients), set(e.kcli.public), {n: dict(a) for n, a in e.kcli.attrs.items()}) == state
    assert any(d.startswith("doc client:") and "chp-doc" in d for d in done)
    c = conf(e)
    assert c["DOC_OIDC_CLIENT"] == "chp-doc"
    assert c["KANIDM_USERINFO_URL"] == "https://idm.iso2.lab.test/oauth2/openid/chp-doc/userinfo"


def test_doc_client_that_is_not_public_is_refused(tmp_path):
    e = Env(tmp_path)
    e.kcli.clients["chp-doc"] = ["CHP doc commands", "https://x"]       # a confidential client by that name
    with pytest.raises(SiteError, match=r"chp-doc .*not a public client.*kanidm system oauth2 delete chp-doc"):
        e.enable()


def test_doc_client_read_back_must_show_the_settings(tmp_path):
    """Read back, never assumed: a Kanidm that did not keep the 8 h refresh expiry is refused, naming it."""
    e = Env(tmp_path)
    orig = e.kcli.__class__.__call__

    def lost(self, argv):
        if argv[:3] == ["system", "oauth2", "set-refresh-token-expiry"]:
            return 0, "", ""
        return orig(self, argv)
    e.kcli.__class__ = type("Lost", (e.kcli.__class__,), {"__call__": lost})
    with pytest.raises(SiteError, match="refresh token expiry"):
        e.enable()


def test_loopback_redirect_must_be_loopback_http():
    from chp_site.kanidm import Kanidm
    k = Kanidm("idm_admin", run=lambda argv: (0, "", ""))
    for bad in ("http://localhost.evil/", "http://10.0.0.1/", "https://127.0.0.1/", "http://127.0.0.1.evil/"):
        with pytest.raises(SiteError):
            k.oauth2_add_loopback_redirect("chp-doc", bad)
    k.oauth2_add_loopback_redirect("chp-doc", "http://127.0.0.1/")


# ---------- the Bearer-only user_oidc provider and the login rewrite ----------

def test_bearer_provider_configured(tmp_path):
    e = Env(tmp_path)
    e.enable()
    p = next(c for c in e.nc.calls if c[0] == "user_oidc:provider" and c[1:2] == ["kanidm-cli"])
    assert "--clientid=chp-doc" in p
    assert "--discoveryuri=https://idm.iso2.lab.test/oauth2/openid/chp-doc/.well-known/openid-configuration" in p
    assert "--check-bearer=1" in p and "--mapping-uid=preferred_username" in p and "--unique-uid=0" in p
    assert "--bearer-provisioning=0" in p                     # auto_provision off for this provider
    assert "--group-provisioning=0" in p                      # a Bearer never changes NextCloud groups
    assert "--scope=openid profile groups" in p
    assert not any(a.startswith("--clientsecret-file") for a in p)          # a public client has no secret
    sc = e.nc.sysconf
    assert sc[("user_oidc", "userinfo_bearer_validation")] == "true"         # every Bearer checked at Kanidm
    assert sc[("user_oidc", "selfencoded_bearer_validation")] == "false"     # never mapped by sub
    # the web provider keeps provider id 1 (the login rewrite sends /login there) and never checks a Bearer
    assert e.nc.provider_ids["kanidm"] == 1 and "--check-bearer=0" in e.nc.provider_args["kanidm"]
    i_web = next(i for i, c in enumerate(e.nc.calls) if c[0] == "user_oidc:provider" and c[1:2] == ["kanidm"])
    i_cli = next(i for i, c in enumerate(e.nc.calls) if c[0] == "user_oidc:provider" and c[1:2] == ["kanidm-cli"])
    assert i_web < i_cli


def test_login_rewrite_needs_the_web_provider_at_id_1(tmp_path):
    e = Env(tmp_path)
    e.nc.provider_ids["old"] = 1                                       # someone made a provider before enable
    with pytest.raises(SiteError, match=r"provider kanidm is id 2.*provider 1"):
        e.enable()
    assert "kanidm-cli" not in e.nc.provider_ids                     # refused before the second provider is made


def test_login_rewrite_shipped_and_included():
    src = (REPO / "lab/docs-spike/proto/nextcloud-login-rewrite.conf").read_text()
    prod = (RPM / "httpd/nextcloud-login-rewrite.conf").read_text()
    directives = lambda t: [ln.strip() for ln in t.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert directives(prod) == directives(src) and len(directives(prod)) == 5          # the spike's five lines
    assert "login/1" in prod and "direct=1" in prod and "redirect_url" in prod
    assert not re.search(r"ocs|remote\.php", " ".join(directives(prod)))               # /ocs keeps the Bearer
    vh = (RPM / "nextcloud-httpd.conf").read_text()
    inc = "Include /etc/httpd/conf.d/chp-nextcloud-login-rewrite.inc"
    assert inc in vh and vh.index("RewriteEngine On") < vh.index(inc) < vh.index("</VirtualHost>")
    spec = (RPM / "chp-documents.spec").read_text()
    m = re.search(r"^(Source\d+):\s+nextcloud-login-rewrite\.conf$", spec, re.M)
    assert m
    n = m.group(1).replace("Source", "")
    assert f"%{{SOURCE{n}}} %{{buildroot}}%{{_sysconfdir}}/httpd/conf.d/chp-nextcloud-login-rewrite.inc" in spec
    assert "%{_sysconfdir}/httpd/conf.d/chp-nextcloud-login-rewrite.inc\n" in spec.split("%files", 1)[1]
    assert '"$here"/httpd/nextcloud-login-rewrite.conf' in (RPM / "build-rpm.sh").read_text()


# ---------- the Compliance and Superseded areas ----------

def test_compliance_areas_read_only(tmp_path):
    e = Env(tmp_path)
    done = e.enable()
    gf = e.root / "data/nextcloud/data/__groupfolders"
    cui, arc, inn = fid(e, "CUI"), fid(e, "Archive"), fid(e, "Internal")
    for f, rel in ((cui, "Compliance"), (inn, "Compliance"), (arc, "Superseded"), (inn, "Compliance/Superseded")):
        assert (gf / str(f) / "files" / rel).is_dir()
        assert f in e.nc.scanned
        groups = ("chp-users",) if f == inn else ("cui-users", "doc-reviewers")   # every group that reaches it
        rules = [r for r in e.nc.folders[f]["rules"] if r[3] == "/" + rel]
        assert sorted(rules) == sorted(["--group", g, "--", "/" + rel, *RO] for g in groups), (f, rel)
    # no rule for a group that is not mapped to the controlled folders (they hold cui-users only)
    assert not [r for f in (cui, arc) for r in e.nc.folders[f]["rules"] if "chp-users" in r]
    mk = [c for c in e.run.calls if c[:2] == ["install", "-d"] and "__groupfolders" in " ".join(c)]
    assert mk and all(c[2:8] == ["-m", "0750", "-o", "apache", "-g", "apache"] for c in mk)
    assert any(c[:2] == ["restorecon", "-R"] and "__groupfolders" in c[2] for c in e.run.calls)
    c = conf(e)
    ids = e.run.fileids
    assert c["CUI_COMPLIANCE_ID"] == str(ids[(cui, "files/Compliance")])
    assert c["INTERNAL_COMPLIANCE_ID"] == str(ids[(inn, "files/Compliance")])
    assert c["CUI_SUPERSEDED_ID"] == str(ids[(arc, "files/Superseded")])
    assert c["INTERNAL_SUPERSEDED_ID"] == str(ids[(inn, "files/Compliance/Superseded")])
    assert len({c[k] for k in ("CUI_COMPLIANCE_ID", "INTERNAL_COMPLIANCE_ID", "CUI_SUPERSEDED_ID",
                               "INTERNAL_SUPERSEDED_ID")}) == 4
    assert any(d.startswith("compliance areas:") for d in done)
    # a second run makes nothing and scans nothing; the ids stay
    n_run, n_occ = len(e.run.calls), len(e.nc.calls)
    e.enable()
    assert not [x for x in e.run.calls[n_run:] if x[:2] == ["install", "-d"] and "__groupfolders" in " ".join(x)]
    assert not [x for x in e.nc.calls[n_occ:] if x[0] == "groupfolders:scan"]
    assert conf(e) == c


def test_compliance_area_left_by_a_failed_run_is_scanned_again(tmp_path):
    """A run that made the folder on the disk but failed before the scan: the next run scans (no mkdir) and finds it."""
    e = Env(tmp_path)
    e.enable()
    inn = fid(e, "Internal")
    e.nc.scanned.discard(inn)
    e.run.fileids.clear()
    n_run, n_occ = len(e.run.calls), len(e.nc.calls)
    e.enable()
    assert ["groupfolders:scan", str(inn)] in e.nc.calls[n_occ:]
    assert not [x for x in e.run.calls[n_run:] if x[:2] == ["install", "-d"] and "__groupfolders" in " ".join(x)]
    assert conf(e)["INTERNAL_COMPLIANCE_ID"] == str(e.run.fileids[(inn, "files/Compliance")])


def test_compliance_area_not_found_after_scan_is_refused(tmp_path):
    e = Env(tmp_path)
    orig = e.nc.__class__.__call__

    def blind(self, argv, env=None):
        if argv[0] == "groupfolders:scan":
            return 0, "", ""                                             # scanned, but nothing registered
        return orig(self, argv, env)
    e.nc.__class__ = type("Blind", (e.nc.__class__,), {"__call__": blind})
    with pytest.raises(SiteError, match=r"CUI/Compliance.*not in NextCloud's file cache after groupfolders:scan"):
        e.enable()
    assert conf(e).get("ENABLED") != "yes"


def test_area_lookup_query_runs_on_the_database():
    """The lookup's SQL against the nightly check's database stand-in: one row for the folder, none for a file."""
    db = DB()
    want = db.file("CUI", "files/Compliance", directory=True)
    db.file("Internal", "files/Compliance", directory=False)            # a FILE named Compliance is not the area
    assert D._area_id(db, str(IDS["CUI"]), "Compliance") == str(want)
    assert D._area_id(db, str(IDS["Internal"]), "Compliance") is None
    assert D._area_id(db, str(IDS["Archive"]), "Superseded") is None


def test_nightly_check_accepts_the_read_only_area_rules_only(tmp_path):
    db = DB()
    comp = db.file("CUI", "files/Compliance", directory=True)
    sup = db.file("Archive", "files/Superseded", directory=True)
    for i, (f, g) in enumerate([(comp, "cui-users"), (comp, "doc-reviewers"), (sup, "cui-users"),
                                (sup, "doc-reviewers")]):
        db.c.execute("INSERT INTO oc_group_folders_acl VALUES (?, ?, 'group', ?, 31, 1)", (200 + i, f, g))
    _, res, _ = do_check(tmp_path, db=db)
    assert res["alerts"] == [], res["alerts"]
    db.c.execute("UPDATE oc_group_folders_acl SET permissions = 7 WHERE fileid = ? AND mapping_id = 'cui-users'",
                 (comp,))                                                # someone made Compliance writable
    _, res, _ = do_check(tmp_path / "b", db=db)
    assert keys(res) == {"acl-other:1"}, res["alerts"]
    db.c.execute("UPDATE oc_group_folders_acl SET permissions = 1 WHERE fileid = ?", (comp,))
    db.c.execute("INSERT INTO oc_group_folders_acl VALUES (299, ?, 'group', 'chp-users', 31, 1)", (comp,))
    _, res, _ = do_check(tmp_path / "c", db=db)              # a group that does not reach CUI: not expected
    assert keys(res) == {"acl-other:1"}, res["alerts"]


# ---------- the DOC_* and CUI_* site keys ----------

def test_doc_keys_validated(tmp_path):
    s = parse_site(DOCSITE + "DOC_ISSO_ACCOUNT=isso1\nDOC_APPROVER_ACCOUNTS=appr1, appr2\n")
    assert s["DOC_ISSO_ACCOUNT"] == "isso1" and s["DOC_APPROVER_ACCOUNTS"] == ["appr1", "appr2"]
    with pytest.raises(SiteError, match="DOC_ISSO_ACCOUNT isso1 is also in DOC_APPROVER_ACCOUNTS"):
        parse_site(DOCSITE + "DOC_ISSO_ACCOUNT=isso1\nDOC_APPROVER_ACCOUNTS=appr1,isso1\n")
    with pytest.raises(SiteError, match="DOC_APPROVER_ACCOUNTS: 'Bad Name' is not a Kanidm account name"):
        parse_site(DOCSITE + "DOC_APPROVER_ACCOUNTS=appr1,Bad Name\n")
    with pytest.raises(SiteError, match="DOC_ISSO_ACCOUNT: 'A. Example' is not a Kanidm account name"):
        parse_site(DOCSITE + "DOC_ISSO_ACCOUNT=A. Example\n")
    with pytest.raises(SiteError, match="DOC_APPROVER_ACCOUNTS: appr1 is listed twice"):
        parse_site(DOCSITE + "DOC_APPROVER_ACCOUNTS=appr1,appr1\n")
    # enable: every name must be a Kanidm account; refused before any change, with a plain message
    e = Env(tmp_path)
    e.kcli.persons = {"isso1", "appr1"}
    site = parse_site(DOCSITE + "DOC_ISSO_ACCOUNT=isso1\nDOC_APPROVER_ACCOUNTS=appr1,appr2\n")
    with pytest.raises(SiteError) as x:
        e.enable(site=site)
    msg = str(x.value)
    assert "DOC_APPROVER_ACCOUNTS names appr2" in msg and "not a Kanidm account" in msg
    assert "Traceback" not in msg and "unexpected output" not in msg
    assert e.run.calls == [c for c in e.run.calls if c[:2] == ["rpm", "-q"]]    # only the MTA probe ran
    assert e.nc.calls == [] and e.records == []
    e.kcli.persons.add("appr2")
    done = e.enable(site=site)
    assert ["person", "get", "appr2"] in kc(e)
    assert any(d.startswith("document approvers:") and "isso1" in d and "appr1, appr2" in d for d in done)


def test_existing_site_without_doc_keys_still_enables(tmp_path):
    e = Env(tmp_path)
    done = e.enable()                                                    # SITE has none of the new keys
    assert not [c for c in kc(e) if c[:2] == ["person", "get"]]
    assert conf(e)["ENABLED"] == "yes"
    assert any(d.startswith("document approvers: not set") and "DOC_ISSO_ACCOUNT" in d for d in done)
    s = parse_site(DOCSITE)
    assert s["DOC_ISSO_ACCOUNT"] == "" and s["DOC_APPROVER_ACCOUNTS"] == []
    assert s["CUI_CONTROLLED_BY"] == s["CUI_CATEGORY"] == s["CUI_POC"] == ""


def test_marking_keys_read_through_sitevars():
    s = parse_site(DOCSITE + "DOC_ISSO_ACCOUNT=isso1\nDOC_APPROVER_ACCOUNTS=appr1,appr2\n"
                   "CUI_CONTROLLED_BY=Example Corp, Security Office\nCUI_CATEGORY=CTI\n"
                   "CUI_POC=A. Example, 555-0100\n")
    v = values(s, HS)
    assert v["CUI_CONTROLLED_BY"] == "Example Corp, Security Office" and v["CUI_CATEGORY"] == "CTI"
    assert v["CUI_POC"] == "A. Example, 555-0100"
    assert v["DOC_ISSO_ACCOUNT"] == "isso1" and v["DOC_APPROVER_ACCOUNTS"] == "appr1,appr2"
    blank = values(parse_site(DOCSITE), HS)
    assert all(blank[k] == "" for k in ("DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS", "CUI_CONTROLLED_BY",
                                        "CUI_CATEGORY", "CUI_POC"))
    with pytest.raises(SiteError, match="CUI_POC"):
        parse_site(DOCSITE + "CUI_POC=" + "x" * 129 + "\n")


def test_template_has_the_new_keys_empty_and_commented():
    t = (REPO / "appliance/site-stick-kit/site.conf.template").read_text()
    for k in ("DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS", "CUI_CONTROLLED_BY", "CUI_CATEGORY", "CUI_POC"):
        assert f"\n{k}=\n" in t, k
    for k in ("DOC_ISSO_ACCOUNT", "CUI_CONTROLLED_BY"):                   # each group of keys is explained first
        assert t[:t.index(f"\n{k}=\n")].rstrip().splitlines()[-1].startswith("#"), k
    parse_site(GOOD + "".join(f"{k}=\n" for k in ("DOC_ISSO_ACCOUNT", "DOC_APPROVER_ACCOUNTS", "CUI_CONTROLLED_BY",
                                                  "CUI_CATEGORY", "CUI_POC")))
