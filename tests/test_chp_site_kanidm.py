import datetime

import pytest

from chp_site.kanidm import Kanidm, PROTECTED, expired, parse_entry, valid_name
from chp_site.sitefile import SiteError

LAB01 = """---
class: account
class: memberof
class: object
class: person
class: posixaccount
directmemberof: idm_all_persons@idm.kanidm.lab.test
directmemberof: lab_users@idm.kanidm.lab.test
displayname: Lab User 1
gidnumber: 2110612348
name: lab01
primary_credential: primary
spn: lab01@idm.kanidm.lab.test
unix_password: unix
"""
NOSESSION = ("\x1b[2m2026-09-30T20:02:43.467354Z\x1b[0m \x1b[31mERROR\x1b[0m kanidm_cli::common: No valid authentication "
             "tokens found for idm_admin.\nthread 'main' panicked at tools/cli/src/cli/common.rs:312:26:\n"
             "note: run with `RUST_BACKTRACE=1`\n")
CONFLICT = ("\x1b[31mERROR\x1b[0m kanidm_cli: OperationId: \"75ec400a\"\n"
            "\x1b[31mERROR\x1b[0m kanidm_cli: HTTP Error: 409 Conflict\n")
TOKEN = ("The person can use one of the following to allow the credential reset\n\nScan this QR Code:\n\n█▀▀█\n\n"
         "This link: https://idm.x.test/ui/reset?token=AbC-123\n"
         "Or run this command: kanidm person credential use-reset-token AbC-123\n"
         "This token will expire at: 2026-09-30T14:10:11-06:00\n")


class Fake:
    def __init__(self, *replies):
        self.calls, self.replies = [], list(replies)

    def __call__(self, argv, timeout=60):
        self.calls.append(argv)
        return self.replies.pop(0)


def test_parse_entry_multi_valued_and_missing():
    e = parse_entry(LAB01)
    assert e["name"] == ["lab01"] and "posixaccount" in e["class"] and e["unix_password"] == ["unix"]
    assert parse_entry("No matching entries\n") is None


def test_parse_entry_refuses_unrecognised_output():
    with pytest.raises(SiteError, match="unexpected output"):
        parse_entry("something else entirely\n")


def test_names():
    assert valid_name("lab01") and valid_name("a") and not valid_name("Lab01") and not valid_name("-x")
    assert not valid_name("a" * 33) and not valid_name("") and not valid_name(None)
    assert PROTECTED == {"admin", "idm_admin"}


def test_expired():
    now = datetime.datetime(2026, 9, 30, 21, 0, tzinfo=datetime.timezone.utc)
    assert expired({"account_expire": ["2026-09-30T20:05:08.933703281Z"]}, now)
    assert not expired({"account_expire": ["2026-10-30T20:05:08Z"]}, now)
    assert not expired({"name": ["x"]}, now)
    with pytest.raises(SiteError, match="account_expire"):
        expired({"account_expire": ["next tuesday"]}, now)


def test_every_command_uses_the_operator_session():
    f = Fake((0, LAB01, ""))
    assert Kanidm("alice", run=f).person("lab01")["name"] == ["lab01"]
    assert f.calls == [["person", "get", "lab01", "-D", "alice"]]


def test_no_session_is_a_readable_error():
    with pytest.raises(SiteError, match=r"not logged in to Kanidm as idm_admin: run `kanidm login -D idm_admin`"):
        Kanidm("idm_admin", run=Fake((101, "", NOSESSION))).person("lab01")


def test_error_uses_last_error_line_without_colour():
    with pytest.raises(SiteError) as e:
        Kanidm("idm_admin", run=Fake((1, "", CONFLICT))).create_person("lab01", "Lab 1")
    assert str(e.value) == "kanidm person create failed: HTTP Error: 409 Conflict"


def test_mutations_argv():
    f = Fake(*[(0, "Success\n", "")] * 6)
    k = Kanidm("idm_admin", run=f)
    k.create_person("lab09", "Lab User 9"); k.posix_set("lab09"); k.add_member("lab_users", "lab09")
    k.remove_member("lab_users", "lab09"); k.expire_now("lab09"); k.clear_expiry("lab09")
    assert [c[:-2] for c in f.calls] == [
        ["person", "create", "lab09", "Lab User 9"], ["person", "posix", "set", "lab09"],
        ["group", "add-members", "lab_users", "lab09"], ["group", "remove-members", "lab_users", "lab09"],
        ["person", "validity", "expire-at", "lab09", "now"], ["person", "validity", "expire-at", "lab09", "clear"]]


def test_reset_token_text_requires_a_token():
    assert "use-reset-token AbC-123" in Kanidm("idm_admin", run=Fake((0, TOKEN, ""))).reset_token_text("lab09")
    with pytest.raises(SiteError, match="no reset token"):
        Kanidm("idm_admin", run=Fake((0, "odd\n", ""))).reset_token_text("lab09")


def test_bad_names_never_reach_the_cli():
    f = Fake()
    with pytest.raises(SiteError, match="not a valid"):
        Kanidm("idm_admin", run=f).person("x; rm -rf /")
    with pytest.raises(SiteError, match="not a valid"):
        Kanidm("Bad Admin", run=f)
    assert f.calls == []


def test_whoami_returns_name():
    assert Kanidm("alice", run=Fake((0, "---\nname: alice\nspn: alice@x\n", ""))).whoami() == "alice"


JWS = "eyJhbGciOiJFUzI1NiJ9AAAAAAAAAAAA.eyJzdWIiOiJ1bml4ZC1jbGkifQAAAAAAA.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"


def test_service_account_and_token():
    f = Fake((0, "No matching entries\n", ""), (0, "Success\n", ""), (0, f"blah\n{JWS}\n", ""))
    k = Kanidm("idm_admin", run=f)
    assert k.service_account_exists("unixd-cli1") is False
    k.service_account_create("unixd-cli1", "unixd on cli1")
    assert k.api_token("unixd-cli1", "cli1-unixd") == JWS
    assert f.calls[1][:4] == ["service-account", "create", "unixd-cli1", "unixd on cli1"]
    assert f.calls[2][:5] == ["service-account", "api-token", "generate", "unixd-cli1", "cli1-unixd"]
    assert "--readwrite" not in f.calls[2]


def test_service_account_names_allow_a_hostname():
    f = Fake((0, "---\nname: unixd-iso4-cli\n", ""))
    assert Kanidm("idm_admin", run=f).service_account_exists("unixd-iso4-cli") is True
    with pytest.raises(SiteError, match="not a valid service account"):
        Kanidm("idm_admin", run=Fake()).service_account_exists("unixd-X;")


def test_api_token_missing_is_an_error():
    with pytest.raises(SiteError, match="no API token"):
        Kanidm("idm_admin", run=Fake((0, "odd\n", ""))).api_token("unixd-cli1", "cli1-unixd")
