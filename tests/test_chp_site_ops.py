import pytest

from chp_site import ops
from chp_site.sitefile import SiteError
from tests.test_chp_site_sshca import ca, keypair  # noqa: F401  (pytest fixture)


class FakeK:
    """In-memory Kanidm: people = {name: entry dict}; records every mutation."""
    def __init__(self, people=None, as_="idm_admin"):
        self.as_, self.people, self.log = as_, people or {}, []

    def person(self, n):
        return self.people.get(n)

    def create_person(self, n, d):
        self.log.append(("create", n, d)); self.people[n] = {"name": [n], "class": ["person"], "directmemberof": []}

    def posix_set(self, n):
        self.log.append(("posix", n)); self.people[n]["class"].append("posixaccount")

    def add_member(self, g, n):
        self.log.append(("add", g, n)); self.people[n]["directmemberof"].append(f"{g}@idm.x")

    def remove_member(self, g, n):
        self.log.append(("remove", g, n))
        self.people[n]["directmemberof"] = [m for m in self.people[n]["directmemberof"] if not m.startswith(g + "@")]

    def reset_token_text(self, n):
        self.log.append(("token", n)); return "This link: https://idm.x/ui/reset?token=T0K\nuse-reset-token T0K\n"

    def expire_now(self, n):
        self.log.append(("expire", n)); self.people[n]["account_expire"] = ["2000-01-01T00:00:00Z"]

    def clear_expiry(self, n):
        self.log.append(("clear", n)); self.people[n].pop("account_expire", None)


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, action, fields, after=False):
        self.calls.append((action, dict(fields), after))


def test_onboard_new_user_full_path(ca, tmp_path):
    k, rec, out = FakeK(), Rec(), tmp_path / "out"
    items = ops.onboard(k, ca, "lab09", "iso3.lab.test", display="Lab 9", groups=("lab_users",),
                        ssh_key=keypair(tmp_path, "u9"), out=out, rec=rec, say=lambda *_: None)
    assert [e[0] for e in k.log] == ["create", "posix", "add", "add", "token"]
    tok = out / "lab09.reset-token.txt"
    assert tok.read_text().endswith("use-reset-token T0K\n") and oct(tok.stat().st_mode & 0o777) == "0o600"
    assert oct(out.stat().st_mode & 0o777) == "0o700" and (out / "lab09-cert.pub").exists()
    done = {i: d for i, d, _ in items}
    assert done["account"] and done["POSIX enabled"] and done["SSH key registered"] and done["SSH certificate issued"]
    assert not done["primary credential"] and not done["POSIX (unix) password"] and not done["Google Authenticator"]
    assert [c[0] for c in rec.calls] == ["onboard", "onboard.done"] and rec.calls[1][2] is True


def test_onboard_is_idempotent_and_skips_the_token_when_credentials_exist(ca, tmp_path):
    k = FakeK({"lab01": {"name": ["lab01"], "class": ["person", "posixaccount"], "directmemberof": ["lab_users@idm.x", "chp_users@idm.x"],
                         "primary_credential": ["primary"], "unix_password": ["unix"]}})
    ops.onboard(k, ca, "lab01", "iso3.lab.test", groups=("lab_users",), out=tmp_path / "o", rec=Rec(), say=lambda *_: None)
    assert k.log == [] and not (tmp_path / "o" / "lab01.reset-token.txt").exists()


def test_onboard_refuses_an_expired_account(ca, tmp_path):     # Review Focus 1: no bypass of ISSO #32
    k, rec = FakeK({"lab04": {"name": ["lab04"], "class": ["person"], "account_expire": ["2000-01-01T00:00:00Z"]}}), Rec()
    with pytest.raises(SiteError, match="chp-site unexpire lab04 --approver"):
        ops.onboard(k, ca, "lab04", "iso3.lab.test", ssh_key=keypair(tmp_path, "u4"), out=tmp_path / "o", rec=rec)
    assert k.log == [] and rec.calls == [] and ca.registered("lab04") is None


def test_onboard_refuses_builtin_admins(ca, tmp_path):
    with pytest.raises(SiteError, match="built-in"):
        ops.onboard(FakeK(), ca, "idm_admin", "x.test", out=tmp_path / "o", rec=Rec())


def test_onboard_audit_failure_changes_nothing(ca, tmp_path):
    def bad(action, fields, after=False):
        raise SiteError("could not write the audit record")
    k = FakeK()
    with pytest.raises(SiteError, match="audit"):
        ops.onboard(k, ca, "lab09", "x.test", out=tmp_path / "o", rec=bad)
    assert k.log == []


def people():
    return {"lab09": {"name": ["lab09"], "class": ["person", "posixaccount"], "directmemberof": ["lab_users@idm.x"]}}


def fan_ok(hosts):
    return [("srv (this server)", True, "not a Kanidm client yet: nothing cached")]


def test_revoke_user_expires_moves_key_audits_and_clears(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "u9"))
    k, rec, fanned = FakeK(people()), Rec(), []
    ops.revoke(k, ca, [], "lab09", rec=rec, fan=lambda h: fanned.append(1) or fan_ok(h), say=lambda *_: None)
    assert k.log == [("expire", "lab09")] and ca.registered("lab09") is None and fanned == [1]
    assert [c[0] for c in rec.calls] == ["revoke", "revoke.done"] and rec.calls[0][1]["scope"] == "account"


def test_revoke_group_membership_only(ca):
    k = FakeK(people())
    ops.revoke(k, ca, [], "lab09", group="lab_users", rec=Rec(), fan=fan_ok, say=lambda *_: None)
    assert k.log == [("remove", "lab_users", "lab09")]


def test_revoke_group_not_a_direct_member_is_refused(ca):
    k = FakeK(people())
    with pytest.raises(SiteError, match="not a direct member of admins_x"):
        ops.revoke(k, ca, [], "lab09", group="admins_x", rec=Rec(), fan=fan_ok)
    assert k.log == []


@pytest.mark.parametrize("who", ["admin", "idm_admin", "alice"])
def test_revoke_refuses_builtins_and_yourself(ca, who):          # Review Focus 2
    k = FakeK({"alice": {"name": ["alice"], "class": ["person"], "directmemberof": []}}, as_="alice")
    with pytest.raises(SiteError, match="refusing"):
        ops.revoke(k, ca, [], who, rec=Rec(), fan=fan_ok)
    assert k.log == []


def test_revoke_unknown_person(ca):
    with pytest.raises(SiteError, match="no Kanidm person lab77"):
        ops.revoke(FakeK(people()), ca, [], "lab77", rec=Rec(), fan=fan_ok)


def test_revoke_with_an_unreachable_client_still_applies_and_says_so(ca):   # Review Focus 3
    k, rec = FakeK(people()), Rec()
    bad = lambda h: [("srv (this server)", True, "ok"), ("cli1", False, "timed out (host off or unreachable?)")]
    with pytest.raises(SiteError, match=r"the Kanidm change IS in effect.*cli1.*~2 min"):
        ops.revoke(k, ca, [], "lab09", rec=rec, fan=bad, say=lambda *_: None)
    assert k.log == [("expire", "lab09")] and [c[0] for c in rec.calls] == ["revoke", "revoke.done"]


def test_revoke_session_lost_midway_writes_no_done_record(ca):      # Review Focus 4
    class Dies(FakeK):
        def expire_now(self, n):
            raise SiteError("not logged in to Kanidm as idm_admin: run `kanidm login -D idm_admin` first")
    rec = Rec()
    with pytest.raises(SiteError, match="not logged in"):
        ops.revoke(Dies(people()), ca, [], "lab09", rec=rec, fan=fan_ok)
    assert [c[0] for c in rec.calls] == ["revoke"]


SITE = {"ISSO_NAME": "Pat Isso", "UNEXPIRE_DELEGATES": ["Sam Deputy"]}


def expired_people():
    return {"lab04": {"name": ["lab04"], "class": ["person", "posixaccount"], "directmemberof": [],
                      "account_expire": ["2000-01-01T00:00:00Z"]}}


@pytest.mark.parametrize("approver", ["Pat Isso", "  pat isso ", "Sam Deputy"])
def test_unexpire_by_isso_or_delegate(ca, approver):
    k, rec = FakeK(expired_people()), Rec()
    ops.unexpire(k, ca, SITE, [], "lab04", approver, "expired by mistake on the wrong ticket", rec=rec, fan=fan_ok,
                 say=lambda *_: None)
    assert k.log == [("clear", "lab04")] and [c[0] for c in rec.calls] == ["unexpire", "unexpire.done"]
    assert rec.calls[0][1]["approver"] == approver.strip() and "wrong ticket" in rec.calls[0][1]["reason"]


def test_unexpire_refuses_anyone_else(ca):
    k, rec = FakeK(expired_people()), Rec()
    with pytest.raises(SiteError, match=r"not the ISSO \(Pat Isso\) or a delegate"):
        ops.unexpire(k, ca, SITE, [], "lab04", "Chris Admin", "please let me back in now", rec=rec, fan=fan_ok)
    assert k.log == [] and rec.calls == []


@pytest.mark.parametrize("reason", ["", "short", "x" * 301, "line one\nline two is here"])
def test_unexpire_needs_a_real_reason(ca, reason):
    with pytest.raises(SiteError, match="--reason"):
        ops.unexpire(FakeK(expired_people()), ca, SITE, [], "lab04", "Pat Isso", reason, rec=Rec(), fan=fan_ok)


def test_unexpire_not_expired_is_refused(ca):
    k = FakeK(people())
    with pytest.raises(SiteError, match="lab09 is not expired"):
        ops.unexpire(k, ca, SITE, [], "lab09", "Pat Isso", "expired by mistake on the wrong ticket", rec=Rec(), fan=fan_ok)
    assert k.log == []


def test_unexpire_reminds_that_the_ssh_key_was_revoked(ca):
    said = []
    ops.unexpire(FakeK(expired_people()), ca, SITE, [], "lab04", "Pat Isso", "expired by mistake on the wrong ticket",
                 rec=Rec(), fan=fan_ok, say=said.append)
    assert any("chp-site onboard lab04 --ssh-key" in s for s in said)


def test_unexpire_builtin_refused(ca):
    with pytest.raises(SiteError, match="built-in"):
        ops.unexpire(FakeK(), ca, SITE, [], "admin", "Pat Isso", "expired by mistake on the wrong ticket", rec=Rec())


ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyHV2oRj8Uf8QdTf6eK8f5dDAXHhpxS5X0mGmAcBwUP x"


def test_onboard_bad_ssh_key_is_refused_before_any_change(ca, tmp_path):    # final review Important #2
    k, rec = FakeK(), Rec()
    with pytest.raises(SiteError, match="FIPS"):
        ops.onboard(k, ca, "lab09", "x.test", ssh_key=ED25519, out=tmp_path / "o", rec=rec)
    assert k.log == [] and rec.calls == [] and not (tmp_path / "o").exists()


def test_onboard_different_key_without_replace_is_refused_before_any_change(ca, tmp_path):
    ca.register("lab09", keypair(tmp_path, "old"))
    k, rec = FakeK(), Rec()
    with pytest.raises(SiteError, match="--replace-key"):
        ops.onboard(k, ca, "lab09", "x.test", ssh_key=keypair(tmp_path, "new"), out=tmp_path / "o", rec=rec)
    assert k.log == [] and rec.calls == []


def test_onboard_always_adds_the_login_group(ca, tmp_path):
    k = FakeK()
    ops.onboard(k, ca, "lab09", "x.test", out=tmp_path / "o", rec=Rec(), say=lambda *_: None)
    assert ("add", "chp_users", "lab09") in k.log


class FakeSA(FakeK):
    def __init__(self):
        super().__init__(); self.sa = set()

    def service_account_exists(self, n):
        return n in self.sa

    def service_account_create(self, n, d):
        self.log.append(("sa-create", n)); self.sa.add(n)

    def add_member(self, g, n):
        self.log.append(("add", g, n))

    def api_token(self, n, label):
        self.log.append(("token", n, label)); return "t" * 20 + ".t" + "t" * 20 + ".t" + "t" * 20


def test_client_token_mints_into_pending(tmp_path):
    from chp_site.hosts import Host
    hosts = [Host("m1", "srv", "10.0.0.1", "server", None), Host("m2", "cli1", "10.0.0.2", "client", None)]
    k, rec = FakeSA(), Rec()
    p = ops.client_token(k, hosts, "cli1", pending=tmp_path / "pend", rec=rec)
    assert p == tmp_path / "pend" / "tokens" / "cli1.token" and oct(p.stat().st_mode & 0o777) == "0o600"
    assert k.log == [("sa-create", "unixd-cli1"), ("add", "idm_unix_authentication_read", "unixd-cli1"),
                     ("token", "unixd-cli1", "cli1-unixd")]
    assert [c[0] for c in rec.calls] == ["client-token", "client-token.done"]


def test_client_token_refuses_unknown_or_server_hosts(tmp_path):
    from chp_site.hosts import Host
    hosts = [Host("m1", "srv", "10.0.0.1", "server", None)]
    with pytest.raises(SiteError, match="not a client in the hosts table"):
        ops.client_token(FakeSA(), hosts, "srv", pending=tmp_path, rec=Rec())
    with pytest.raises(SiteError, match="not a client in the hosts table"):
        ops.client_token(FakeSA(), hosts, "nope", pending=tmp_path, rec=Rec())


def test_onboard_refuses_names_that_collide_with_local_accounts(ca, tmp_path):   # final review I1
    pw = tmp_path / "passwd"; pw.write_text("root:x:0:0::/root:/bin/bash\nsvcx:x:990:990::/:/sbin/nologin\n")
    gr = tmp_path / "group"; gr.write_text("wheel:x:10:\nlocalgrp:x:991:\n")
    for name in ("diag", "chpcache", "chpadmin", "root", "svcx"):
        k = FakeK()
        with pytest.raises(SiteError, match="local account"):
            ops.onboard(k, ca, name, "x.test", out=tmp_path / "o", rec=Rec(), passwd=pw, group=gr)
        assert k.log == []
    for g in ("wheel", "adm", "localgrp", "sudo"):
        k = FakeK()
        with pytest.raises(SiteError, match="local group"):
            ops.onboard(k, ca, "lab09", "x.test", groups=(g,), out=tmp_path / "o", rec=Rec(), passwd=pw, group=gr)
        assert k.log == []
