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
    assert [e[0] for e in k.log] == ["create", "posix", "add", "token"]
    tok = out / "lab09.reset-token.txt"
    assert tok.read_text().endswith("use-reset-token T0K\n") and oct(tok.stat().st_mode & 0o777) == "0o600"
    assert oct(out.stat().st_mode & 0o777) == "0o700" and (out / "lab09-cert.pub").exists()
    done = {i: d for i, d, _ in items}
    assert done["account"] and done["POSIX enabled"] and done["SSH key registered"] and done["SSH certificate issued"]
    assert not done["primary credential"] and not done["POSIX (unix) password"] and not done["Google Authenticator"]
    assert [c[0] for c in rec.calls] == ["onboard", "onboard.done"] and rec.calls[1][2] is True


def test_onboard_is_idempotent_and_skips_the_token_when_credentials_exist(ca, tmp_path):
    k = FakeK({"lab01": {"name": ["lab01"], "class": ["person", "posixaccount"], "directmemberof": ["lab_users@idm.x"],
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
